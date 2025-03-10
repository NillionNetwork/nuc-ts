import type { Selector } from "#/types";

export function applySelector(selector: Selector, value: unknown): unknown {
  let result = value;
  for (const label of selector) {
    if (typeof result === "object") {
      const record = result as Record<string, unknown>;
      if (label in record) {
        result = record[label];
      } else {
        return undefined;
      }
    }
  }
  return result;
}
