import { SelectorSchema } from "#/types";

export function applySector(expr: string, value: unknown): unknown {
  let result = value;
  const selector = SelectorSchema.parse(expr);
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
