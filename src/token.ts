import type { Temporal } from "temporal-polyfill";
import type { Command, DelegationBody, InvocationBody } from "#/types";

export class Did {
  constructor(public readonly publicKey: Uint8Array) {}

  toString(): string {
    return `did:nil:${Buffer.from(this.publicKey).toString("hex")}`;
  }

  static fromHex(hex: string): Did {
    return new Did(Uint8Array.from(Buffer.from(hex, "hex")));
  }
}

export class NucToken {
  constructor(
    private readonly data: {
      issuer: Did;
      audience: Did;
      subject: Did;
      command: Command;
      body: DelegationBody | InvocationBody;
      nonce: Uint8Array;
      proofs?: Array<Uint8Array>;
      notBefore?: Temporal.Instant;
      expiresAt?: Temporal.Instant;
      meta?: Record<string, unknown>;
    },
  ) {}

  get issuer(): Did {
    return this.data.issuer;
  }

  get audience(): Did {
    return this.data.audience;
  }

  get subject(): Did {
    return this.data.subject;
  }

  get command(): Command {
    return this.data.command;
  }

  get body(): InvocationBody | DelegationBody {
    return this.data.body;
  }

  get nonce(): Uint8Array {
    return this.data.nonce;
  }

  get proofs(): Array<Uint8Array> {
    return this.data.proofs ? this.data.proofs : [];
  }

  get notBefore(): Temporal.Instant | undefined {
    return this.data.notBefore;
  }

  get expiresAt(): Temporal.Instant | undefined {
    return this.data.expiresAt;
  }

  get meta(): Record<string, unknown> | undefined {
    return this.data.meta;
  }
}
