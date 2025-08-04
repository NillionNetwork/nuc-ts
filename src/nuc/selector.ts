import _ from "es-toolkit/compat";
import { z } from "zod";

/**
 * Selector format validation for "simple" non-indexed paths
 *
 * @example
 * ```ts
 * SELECTOR_REGEX.test(".")             // true
 * SELECTOR_REGEX.test("$.")            // true
 * SELECTOR_REGEX.test("")              // false
 * SELECTOR_REGEX.test(".foo.bar")      // true
 * SELECTOR_REGEX.test("$.foo.bar")     // true
 * SELECTOR_REGEX.test("$.foo[0].bar")  // false, index paths not supported
 * ```
 */
const SELECTOR_REGEX = /^(\$)?\.([a-zA-Z0-9_-]+(\.[a-zA-Z0-9_-]+)*)?$/;

export const SelectorSchema = z
  .string()
  .regex(SELECTOR_REGEX, "Invalid selector format")
  .brand<"Selector">();

export type Selector = z.infer<typeof SelectorSchema>;

/**
 * Apply a selector to extract a value from token or context
 */
export function applySelector<
  T extends Record<string, unknown> = Record<string, unknown>,
  C extends Record<string, unknown> = Record<string, unknown>,
  R = unknown,
>(selector: Selector, token: T, context: C): R | undefined {
  // Handle identity selectors (eg base cases)
  if (selector === ".") return token as unknown as R;
  if (selector === "$.") return context as unknown as R;

  // Handle path selectors
  const isContext = selector.startsWith("$");
  const path = selector.slice(isContext ? 2 : 1);
  const target = isContext ? context : token;

  return _.get(target, path) as R;
}
