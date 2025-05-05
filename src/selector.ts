import { z } from "zod";

const ALPHABET_LABEL = /[a-zA-Z0-9_-]+/;

export type SelectorTarget = "token" | "context";

export const SelectorSchema = z
  .string()
  .transform((selector) =>
    selector.startsWith("$")
      ? { selector: selector.slice(1), target: "context" as SelectorTarget }
      : { selector, target: "token" as SelectorTarget },
  )
  .refine(
    ({ selector }) => selector.startsWith("."),
    "selector must start with '.' or '$'",
  )
  .transform(({ selector, target }) => {
    const s = selector.slice(1);
    const labels = s ? s.split(".") : [];
    return { labels, target };
  })
  .refine(({ labels }) => labels.every(Boolean), "empty attribute")
  .refine(
    ({ labels, target }) =>
      (target === "context" && labels.length > 0) || target === "token",
  )
  .refine(
    ({ labels }) => labels.every((label) => ALPHABET_LABEL.test(label)),
    "invalid attribute character",
  )
  .transform(({ labels, target }) => new Selector(labels, target));

/**
 * A selector that specifies a path within a JSON object to be matched.
 */
export class Selector {
  constructor(
    private readonly path: Array<string>,
    private readonly target: SelectorTarget,
  ) {}

  /**
   * Apply a selector on a value and return the matched value, if any.
   * @param value The value that this selector could be applied to.
   * @param context The context that this selector could be applied to.
   */
  apply<T = unknown>(value: T, context: Record<string, T>): T {
    switch (this.target) {
      case "token":
        return Selector.applyOnValue(this.path, value) as T;
      case "context": {
        if (!this.path) return undefined as T;
        return Selector.applyOnValue(
          this.path.slice(1),
          context[this.path[0]],
        ) as T;
      }
    }
  }

  static applyOnValue<T = unknown>(path: Array<string>, value: T): T {
    let result = value;
    for (const label of path) {
      if (result !== null && typeof result === "object") {
        const record = result as Record<string, unknown>;
        if (label in record) {
          result = record[label] as T;
        } else {
          return undefined as T;
        }
      }
    }
    return result;
  }
  /**
   * Convert this selector into a string.
   */
  toString(): string {
    const prefix = this.target === "token" ? "" : "$";
    return `${prefix}.${this.path.join(".")}`;
  }
}
