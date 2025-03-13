import { Temporal } from "temporal-polyfill";
import { z } from "zod";
import { type Policy, PolicySchema } from "#/policy";

const DID_EXPRESSION = /^did:nil:([a-zA-Z0-9]{66})$/;

export const DidSchema = z
  .string()
  .transform((did) => DID_EXPRESSION.exec(did))
  .refine((match) => match !== null, "invalid DID")
  .transform((match) => Did.fromHex(match[1]));

export class Did {
  constructor(public readonly publicKey: Uint8Array) {}

  toString(): string {
    return `did:nil:${Buffer.from(this.publicKey).toString("hex")}`;
  }

  static fromHex(hex: string): Did {
    return new Did(Uint8Array.from(Buffer.from(hex, "hex")));
  }
}

export const CommandSchema = z
  .string()
  .startsWith("/", "command must start with '/'")
  .transform((selector) => {
    const s = selector.slice(1);
    if (!s) return [];
    return s.split("/");
  })
  .refine((labels) => labels.every(Boolean), "empty command")
  .transform((segments) => {
    return new Command(segments);
  });

export class Command {
  constructor(public readonly segments: Array<string>) {}

  toString(): string {
    return `/${this.segments.join("/")}`;
  }
}

export const InvocationBodySchema = z
  .record(z.string(), z.unknown())
  .transform((args) => new InvocationBody(args));

export class InvocationBody {
  constructor(public readonly args: Record<string, unknown>) {}
}

export const DelegationBodySchema = z
  .array(PolicySchema)
  .transform((body) => new DelegationBody(body as Array<Policy>));
export class DelegationBody {
  constructor(public readonly policies: Array<Policy>) {}
}

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
    prf: z.array(z.string()).default([]),
  })
  .transform((token) => {
    return new NucToken({
      issuer: token.iss,
      audience: token.aud,
      subject: token.sub,
      command: token.cmd,
      body: tokenBody(token.args, token.pol),
      nonce: new Uint8Array(Buffer.from(token.nonce, "hex")),
      proofs: token.prf.map((prf) => new Uint8Array(Buffer.from(prf, "hex"))),
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

export const NucTokenDataSchema = z.object({
  issuer: z.instanceof(Did),
  audience: z.instanceof(Did),
  subject: z.instanceof(Did),
  notBefore: z.instanceof(Temporal.Instant).optional(),
  expiresAt: z.instanceof(Temporal.Instant).optional(),
  command: z.instanceof(Command),
  body: z.union([z.instanceof(DelegationBody), z.instanceof(InvocationBody)]),
  meta: z.record(z.string(), z.unknown()).optional(),
  nonce: z.instanceof(Uint8Array),
  proofs: z.array(z.instanceof(Uint8Array)),
});

export type NucTokenData = z.infer<typeof NucTokenDataSchema>;

export class NucToken {
  constructor(private readonly _data: NucTokenData) {}

  get issuer(): Did {
    return this._data.issuer;
  }

  get audience(): Did {
    return this._data.audience;
  }

  get subject(): Did {
    return this._data.subject;
  }

  get command(): Command {
    return this._data.command;
  }

  get body(): InvocationBody | DelegationBody {
    return this._data.body;
  }

  get nonce(): Uint8Array {
    return this._data.nonce;
  }

  get proofs(): Array<Uint8Array> {
    return this._data.proofs ? this._data.proofs : [];
  }

  get notBefore(): Temporal.Instant | undefined {
    return this._data.notBefore;
  }

  get expiresAt(): Temporal.Instant | undefined {
    return this._data.expiresAt;
  }

  get meta(): Record<string, unknown> | undefined {
    return this._data.meta;
  }

  toString(): string {
    const token: Record<string, unknown> = {
      iss: this.issuer.toString(),
      aud: this.audience.toString(),
      sub: this.subject.toString(),
      nbf: this.notBefore ? this.notBefore.epochMilliseconds : undefined,
      exp: this.expiresAt ? this.expiresAt.epochMilliseconds : undefined,
      cmd: this.command.toString(),
      args: this.body instanceof InvocationBody ? this.body.args : undefined,
      pol:
        this.body instanceof DelegationBody
          ? this.body.policies.map((policy) => policy.serialize())
          : undefined,
      meta: this.meta,
      nonce: Buffer.from(this.nonce).toString("hex"),
      prf:
        this.proofs && this.proofs.length > 0
          ? this.proofs.map((proof) => Buffer.from(proof).toString("hex"))
          : undefined,
    };
    return JSON.stringify(token);
  }
}
