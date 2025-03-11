import type { Temporal } from "temporal-polyfill";
import type { Command, DelegationBody, InvocationBody } from "#/types";

export class Did {
  public readonly publicKey: Uint8Array;

  constructor(publicKey: Uint8Array) {
    this.publicKey = publicKey;
  }

  toString(): string {
    return `did:nil:${Buffer.from(this.publicKey).toString("hex")}`;
  }

  static fromHex(hex: string): Did {
    return new Did(Uint8Array.from(Buffer.from(hex, "hex")));
  }
}

export class NucToken {
  public readonly issuer: Did;
  public readonly audience: Did;
  public readonly subject: Did;
  public readonly notBefore?: Temporal.Instant;
  public readonly expiresAt?: Temporal.Instant;
  public readonly command: Command;
  public readonly body: DelegationBody | InvocationBody;
  public readonly proofs: Array<Uint8Array>;
  public readonly nonce: Uint8Array;
  public readonly meta?: Record<string, unknown>;

  constructor(
    issuer: Did,
    audience: Did,
    subject: Did,
    command: Command,
    body: DelegationBody | InvocationBody,
    nonce: Uint8Array,
    proofs: Array<Uint8Array> = [],
    notBefore?: Temporal.Instant,
    expiresAt?: Temporal.Instant,
    meta?: Record<string, unknown>,
  ) {
    this.issuer = issuer;
    this.audience = audience;
    this.subject = subject;
    this.notBefore = notBefore;
    this.expiresAt = expiresAt;
    this.command = command;
    this.body = body;
    this.proofs = proofs;
    this.nonce = nonce;
    this.meta = meta;
  }
}
