import type { Selector } from "#/types";

export function applySelector<T = unknown>(
  selector: Selector,
  value: unknown,
): T {
  let result = value;
  for (const label of selector) {
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
