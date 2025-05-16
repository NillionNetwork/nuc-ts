import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import equal from "fast-deep-equal/es6";
import { Temporal } from "temporal-polyfill";
import { z } from "zod";
import { type Policy, PolicySchema } from "#/policy";
import { type Hex, HexSchema } from "#/utils";

const DID_EXPRESSION = /^did:nil:([a-zA-Z0-9]{66})$/;

export const DidSchema = z
  .string()
  .transform((did) => DID_EXPRESSION.exec(did))
  .refine((match) => match !== null, "invalid DID")
  .transform((match) => Did.fromHex(match[1]));

export type DidString = `did:nil:${string}`;

/**
 * A class representing a Decentralized Identifier (DID).
 */
export class Did {
  /**
   *
   * Creates a new DID for the given public key.
   * @param publicKey Public key in bytes format.
   */
  constructor(public readonly publicKey: Uint8Array) {}

  /**
   * Convert this DID into a string.
   */
  toString(): DidString {
    return `did:nil:${this.publicKeyAsHex()}`;
  }

  /**
   * Get the public which this DID represents.
   */
  publicKeyAsHex(): string {
    return bytesToHex(this.publicKey);
  }

  /**
   * Check if this and another DID are equals.
   * @param other The other DID which will be used for the equality operation.
   */
  isEqual(other: Did): boolean {
    return (
      Buffer.from(this.publicKey).compare(Buffer.from(other.publicKey)) === 0
    );
  }

  /**
   * Creates a new DID for the given public key.
   * @param hex Public key in hex format.
   */
  static fromHex(hex: Hex): Did {
    return new Did(hexToBytes(hex));
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

/**
 * A command to be invoked.
 */
export class Command {
  constructor(public readonly segments: Array<string>) {}

  /**
   * Check if this command is an attenuation of another one.
   * @param other The command for which this command is attenuation.
   */
  isAttenuationOf(other: Command): boolean {
    return (
      this.segments.length >= other.segments.length &&
      equal(other.segments, this.segments.slice(0, other.segments.length))
    );
  }

  /**
   * Convert this command into a string.
   */
  toString(): string {
    return `/${this.segments.join("/")}`;
  }
}
export const REVOKE_COMMAND = new Command(["nuc", "revoke"]);

export const InvocationBodySchema = z
  .record(z.string(), z.unknown())
  .transform((args) => new InvocationBody(args));

/**
 * Body of an invocation token.
 */
export class InvocationBody {
  constructor(public readonly args: Record<string, unknown>) {}
}

export const DelegationBodySchema = z
  .array(PolicySchema)
  .transform((body) => new DelegationBody(body as Array<Policy>));

/**
 * Body of a delegation token.
 */
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
    nonce: HexSchema,
    prf: z.array(z.string()).default([]),
  })
  .transform((token) => {
    return new NucToken({
      issuer: token.iss,
      audience: token.aud,
      subject: token.sub,
      command: token.cmd,
      body: tokenBody(token.args, token.pol),
      nonce: token.nonce,
      proofs: token.prf.map((prf) => new Uint8Array(Buffer.from(prf, "hex"))),
      notBefore: token.nbf
        ? Temporal.Instant.fromEpochMilliseconds(token.nbf * 1000)
        : undefined,
      expiresAt: token.exp
        ? Temporal.Instant.fromEpochMilliseconds(token.exp * 1000)
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
  nonce: HexSchema,
  proofs: z.array(z.instanceof(Uint8Array)),
});

export type NucTokenData = z.infer<typeof NucTokenDataSchema>;

/**
 * A class representing a NUC token.
 */
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

  get nonce(): Hex {
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

  /**
   * Convert this token into JSON.
   */
  toJson(): Record<string, unknown> {
    return {
      iss: this.issuer.toString(),
      aud: this.audience.toString(),
      sub: this.subject.toString(),
      nbf: this.notBefore
        ? Math.floor(this.notBefore.epochMilliseconds / 1000)
        : undefined,
      exp: this.expiresAt
        ? Math.floor(this.expiresAt.epochMilliseconds / 1000)
        : undefined,
      cmd: this.command.toString(),
      args: this.body instanceof InvocationBody ? this.body.args : undefined,
      pol:
        this.body instanceof DelegationBody
          ? this.body.policies.map((policy) => policy.serialize())
          : undefined,
      meta: this.meta,
      nonce: this.nonce,
      prf:
        this.proofs && this.proofs.length > 0
          ? this.proofs.map((proof) => bytesToHex(proof))
          : undefined,
    };
  }

  /**
   * Convert this command into a string.
   */
  toString(): string {
    return JSON.stringify(this.toJson());
  }
}
