import { bytesToHex } from "@noble/hashes/utils";
import { Temporal } from "temporal-polyfill";
import type { NucTokenEnvelope } from "#/envelope";
import { Keypair } from "#/keypair";
import type { Policy } from "#/policy";
import {
  type Command,
  DelegationBody,
  Did,
  InvocationBody,
  NucToken,
  NucTokenDataSchema,
} from "#/token";
import { base64UrlEncode, type Hex, randomBytes } from "#/utils";

const DEFAULT_NONCE_LENGTH = 16;

/**
 * Builder for a NUC token.
 */
export class NucTokenBuilder {
  private _audience?: Did;
  private _subject?: Did;
  private _notBefore?: Temporal.Instant;
  private _expiresAt?: Temporal.Instant;
  private _command?: Command;
  private _meta?: Record<string, unknown>;
  private _nonce?: Hex;
  private _proof?: NucTokenEnvelope;

  private constructor(private _body: DelegationBody | InvocationBody) {}

  /**
   * Create a new token builder for a delegation token.
   * @param policies The policies to use in the delegation.
   */
  static delegation(policies: Array<Policy>): NucTokenBuilder {
    return new NucTokenBuilder(new DelegationBody(policies));
  }

  /**
   * Creates a new token builder for an invocation.
   * @param args The arguments to use in the invocation.
   */
  static invocation(args: Record<string, unknown>): NucTokenBuilder {
    return new NucTokenBuilder(new InvocationBody(args));
  }

  /**
   * Create a NUC token builder that pulls basic properties from a given NUC token.
   *
   * This pulls the following properties from the given envelope:
   *
   *  * command
   *  * subject
   *
   * @param envelope The envelope to extend.
   */
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

  /**
   * Set the audience for the token to be built.
   *
   * The audience must be the entity this token is going to be sent to.
   *
   * @param audience The audience of the token.
   */
  audience(audience: Did): NucTokenBuilder {
    this._audience = audience;
    return this;
  }

  /**
   * Set the body for the token being built.
   *
   * @param body The body for the token.
   */
  body(body: DelegationBody | InvocationBody): NucTokenBuilder {
    this._body = body;
    return this;
  }

  /**
   * Set the subject for the token to be built.
   *
   * @param subject The subject of the token.
   */
  subject(subject: Did): NucTokenBuilder {
    this._subject = subject;
    return this;
  }

  /**
   * Set the token's `not before` instant.
   *
   * @param notBeforeInSeconds The Unix timestamp (in seconds) at which the token becomes valid.
   */
  notBefore(notBeforeInSeconds: number): NucTokenBuilder {
    this._notBefore = Temporal.Instant.fromEpochMilliseconds(
      notBeforeInSeconds * 1000,
    );
    return this;
  }

  /**
   * Set the token's `expires at` instant.
   *
   * @param expiresAtInSeconds The Unix timestamp (in seconds) at which the token expires.
   */
  expiresAt(expiresAtInSeconds: number): NucTokenBuilder {
    this._expiresAt = Temporal.Instant.fromEpochMilliseconds(
      expiresAtInSeconds * 1000,
    );
    return this;
  }

  /**
   * Set the command for the token to be built.
   *
   * @param command The command for the token to be built.
   */
  command(command: Command): NucTokenBuilder {
    this._command = command;
    return this;
  }

  /**
   * Set the metadata for the token to be built.
   *
   * @param meta The metadata for the built token.
   */
  meta(meta: Record<string, unknown>): NucTokenBuilder {
    this._meta = meta;
    return this;
  }

  /**
   * Set the nonce for the token to be built.
   *
   * @param nonce The nonce to be set.
   *
   * The nonce doesn't have to be explicitly set and it will default to a random 16 bytes long bytestring if not set.
   */
  nonce(nonce: Hex): NucTokenBuilder {
    this._nonce = nonce;
    return this;
  }

  /**
   * Set the proof for the token to be built.
   *
   * It's recommended to call :meth:`NucTokenBuilder.extending` which also takes care of pulling other important fields.
   *
   * @param proof The token to be used as proof.
   */
  proof(proof: NucTokenEnvelope): NucTokenBuilder {
    this._proof = proof;
    return this;
  }

  /**
   * Build the token, signing it using the given private key.
   *
   * @param key The key to use to sing the token.
   */
  build(key: Uint8Array): string {
    const keypair = new Keypair(key);
    const proof = this._proof;
    if (proof) {
      proof.validateSignatures();
    }
    const data = NucTokenDataSchema.parse({
      body: this._body,
      issuer: new Did(keypair.publicKey()),
      audience: this._audience,
      subject: this._subject,
      notBefore: this._notBefore,
      expiresAt: this._expiresAt,
      command: this._command,
      meta: this._meta,
      nonce: this._nonce
        ? this._nonce
        : bytesToHex(randomBytes(DEFAULT_NONCE_LENGTH)),
      proofs: proof ? [proof.token.computeHash()] : [],
    });
    let token = base64UrlEncode(new NucToken(data).toString());
    const header = base64UrlEncode('{"alg":"ES256K"}');
    token = `${header}.${token}`;

    const signature = keypair.sign(token);
    token = `${token}.${base64UrlEncode(signature)}`;
    if (this._proof) {
      const allProofs = [this._proof.token, ...this._proof.proofs];
      token = `${token}/${allProofs.map((proof) => proof.serialize()).join("/")}`;
    }
    return token;
  }
}
