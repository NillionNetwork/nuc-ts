import * as crypto from "node:crypto";
import { secp256k1 } from "@noble/curves/secp256k1";
import type { Temporal } from "temporal-polyfill";
import type { NucTokenEnvelope } from "#/envelope";
import {
  type Command,
  DelegationBody,
  Did,
  InvocationBody,
  NucToken,
  NucTokenDataSchema,
} from "#/token";
import type { Policy } from "#/types";
import { base64UrlEncode } from "#/utils";

const DEFAULT_NONCE_LENGTH = 16;

export class NucTokenBuilder {
  private _audience?: Did;
  private _subject?: Did;
  private _notBefore?: Temporal.Instant;
  private _expiresAt?: Temporal.Instant;
  private _command?: Command;
  private _meta?: Record<string, unknown>;
  private _nonce?: Uint8Array;
  private _proof?: NucTokenEnvelope;

  private constructor(private _body: DelegationBody | InvocationBody) {}

  static delegation(policies: Array<Policy>): NucTokenBuilder {
    return new NucTokenBuilder(new DelegationBody(policies));
  }

  static invocation(args: Record<string, unknown>): NucTokenBuilder {
    return new NucTokenBuilder(new InvocationBody(args));
  }

  static extending(envelope: NucTokenEnvelope): NucTokenBuilder {
    const token = envelope.token;
    if (token.token.body instanceof InvocationBody) {
      throw Error("cannot extend an invocation");
    }
    return new NucTokenBuilder(token.token.body)
      .proof(envelope)
      .command(token.token.command)
      .subject(token.token.subject);
  }

  audience(audience: Did): NucTokenBuilder {
    this._audience = audience;
    return this;
  }

  subject(subject: Did): NucTokenBuilder {
    this._subject = subject;
    return this;
  }

  notBefore(notBefore: Temporal.Instant): NucTokenBuilder {
    this._notBefore = notBefore;
    return this;
  }

  expiresAt(expiresAt: Temporal.Instant): NucTokenBuilder {
    this._expiresAt = expiresAt;
    return this;
  }

  command(command: Command): NucTokenBuilder {
    this._command = command;
    return this;
  }

  meta(meta: Record<string, unknown>): NucTokenBuilder {
    this._meta = meta;
    return this;
  }

  nonce(nonce: Uint8Array): NucTokenBuilder {
    this._nonce = nonce;
    return this;
  }

  proof(proof: NucTokenEnvelope): NucTokenBuilder {
    this._proof = proof;
    return this;
  }

  build(key: Uint8Array): string {
    const proof = this._proof;
    if (proof) {
      proof.validateSignatures();
    }
    const data = NucTokenDataSchema.parse({
      body: this._body,
      issuer: new Did(secp256k1.getPublicKey(key, true)),
      audience: this._audience,
      subject: this._subject,
      notBefore: this._notBefore,
      expiresAt: this._expiresAt,
      command: this._command,
      meta: this._meta,
      nonce: this._nonce
        ? this._nonce
        : crypto.randomBytes(DEFAULT_NONCE_LENGTH),
      proofs: proof ? [proof.token.computeHash()] : [],
    });
    let token = base64UrlEncode(new NucToken(data).toString());
    const header = base64UrlEncode('{"alg":"ES256K"}');
    token = `${header}.${token}`;

    const msg = Uint8Array.from(Buffer.from(token));
    const signature = secp256k1.sign(msg, key, { prehash: true });

    token = `${token}.${base64UrlEncode(signature.toCompactRawBytes())}`;
    if (this._proof) {
      const allProofs = [this._proof.token, ...this._proof.proofs];
      token = `${token}/${allProofs.map((proof) => proof.toString()).join("/")}`;
    }
    return token;
  }
}
