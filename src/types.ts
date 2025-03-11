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
  );
export type Selector = z.infer<typeof SelectorSchema>;

export const EqualsSchema = z
  .tuple([z.literal("=="), SelectorSchema, z.unknown()])
  .transform((operator) => {
    return {
      type: "equals",
      selector: operator[1],
      value: operator[2],
    };
  });
export type Equals = z.infer<typeof EqualsSchema>;

export const NotEqualsSchema = z
  .tuple([z.literal("!="), SelectorSchema, z.unknown()])
  .transform((operator) => {
    return {
      type: "notEquals",
      selector: operator[1],
      value: operator[2],
    };
  });
export type NotEquals = z.infer<typeof NotEqualsSchema>;

export const AnyOfSchema = z
  .tuple([z.literal("anyOf"), SelectorSchema, z.array(z.unknown())])
  .transform((operator) => {
    return {
      type: "anyOf",
      selector: operator[1],
      options: operator[2],
    };
  });
export type AnyOf = z.infer<typeof AnyOfSchema>;

export const OperatorSchema = z.union([
  EqualsSchema,
  NotEqualsSchema,
  AnyOfSchema,
]);
export type Operator = z.infer<typeof OperatorSchema>;

export const AndSchema = z
  .lazy(() => z.tuple([z.literal("and"), z.array(PolicySchema)]))
  .transform((connector) => {
    return {
      type: "and",
      conditions: connector[1],
    };
  });
export type And = z.infer<typeof AndSchema>;

export const OrSchema = z
  .lazy(() => z.tuple([z.literal("or"), z.array(PolicySchema)]))
  .transform((connector) => {
    return {
      type: "or",
      conditions: connector[1],
    };
  });
export type Or = z.infer<typeof OrSchema>;

export const NotSchema = z
  .lazy(() => z.tuple([z.literal("not"), PolicySchema]))
  .transform((connector) => {
    return {
      type: "not",
      condition: connector[1],
    };
  });
export type Not = z.infer<typeof NotSchema>;

export const ConnectorSchema = z.lazy(() =>
  z.union([AndSchema, OrSchema, NotSchema]),
);
export type Connector = z.infer<typeof ConnectorSchema>;

export const PolicySchema: z.ZodType<unknown> = z.lazy(() =>
  z.union([ConnectorSchema, OperatorSchema]),
);
export type Policy = z.infer<typeof PolicySchema>;
