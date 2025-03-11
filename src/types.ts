import { Temporal } from "temporal-polyfill";
import { z } from "zod";
import { Did, NucToken } from "#/token";

const ALPHABET_LABEL = /[a-zA-Z0-9_-]+/;
const DID_EXPRESSION = /^did:nil:([a-zA-Z0-9]{66})$/;

export const DidSchema = z
  .string()
  .transform((did) => DID_EXPRESSION.exec(did))
  .refine((match) => match !== null, "invalid DID")
  .transform((match) => Did.fromHex(match[1]));

export const CommandSchema = z
  .string()
  .startsWith("/", "command must start with '/'")
  .transform((selector) => {
    const s = selector.slice(1);
    if (!s) return [];
    return s.split("/");
  })
  .refine((labels) => labels.every(Boolean), "empty command")
  .transform((commands) => {
    return { segments: commands };
  });
export type Command = z.infer<typeof CommandSchema>;

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

export const InvocationBodySchema = z.record(z.string(), z.unknown());
export type InvocationBody = z.infer<typeof InvocationBodySchema>;

export const DelegationBodySchema = z.array(PolicySchema);
export type DelegationBody = z.infer<typeof DelegationBodySchema>;

export const NucTokenSchema = z
  .object({
    iss: DidSchema,
    aud: DidSchema,
    sub: DidSchema,
    nbf: z.number().optional(),
    exp: z.number().optional(),
    cmd: CommandSchema,
    args: InvocationBodySchema.optional(),
    pol: DelegationBodySchema.optional(),
    meta: z.record(z.string(), z.unknown()).optional(),
    nonce: z.string(),
    prf: z.array(z.string()).optional(),
  })
  .transform((token) => {
    return new NucToken({
      issuer: token.iss,
      audience: token.aud,
      subject: token.sub,
      command: token.cmd,
      body: tokenBody(token.args, token.pol),
      nonce: new Uint8Array(Buffer.from(token.nonce, "hex")),
      proofs: token.prf?.map((prf) => new Uint8Array(Buffer.from(prf, "hex"))),
      notBefore: token.nbf
        ? Temporal.Instant.fromEpochMilliseconds(token.nbf)
        : undefined,
      expiresAt: token.exp
        ? Temporal.Instant.fromEpochMilliseconds(token.exp)
        : undefined,
      meta: token.meta,
    });
  });

function tokenBody(
  args: InvocationBody | undefined,
  pol: DelegationBody | undefined,
): InvocationBody | DelegationBody {
  if (args !== undefined && pol !== undefined)
    throw Error("one of 'args' and 'pol' must be set");
  if (args !== undefined) return args;
  if (pol !== undefined) return pol;
  throw Error("'args' and 'pol' can't both be set");
}
