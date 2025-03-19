import { z } from "zod";

const ALPHABET_LABEL = /[a-zA-Z0-9_-]+/;

export const SelectorSchema = z
  .string()
  .startsWith(".", "selector must start with '.'")
  .transform((selector) => {
    const s = selector.slice(1);
    if (!s) return [];
    return s.split(".");
  })
  .refine((labels) => labels.every(Boolean), "empty attribute")
  .refine(
    (labels) => labels.every((label) => ALPHABET_LABEL.test(label)),
    "invalid attribute character",
  )
  .transform((labels) => new Selector(labels));

export class Selector {
  constructor(private readonly path: Array<string>) {}

  apply<T = unknown>(value: unknown): T {
    let result = value;
    for (const label of this.path) {
      if (result !== null && typeof result === "object") {
        const record = result as Record<string, unknown>;
        if (label in record) {
          result = record[label];
        } else {
          return undefined as T;
        }
      }
    }
    return result as T;
  }

  toString(): string {
    return `.${this.path.join(".")}`;
  }
}
