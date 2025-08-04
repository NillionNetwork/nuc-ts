import { bytesToHex, randomBytes } from "@noble/hashes/utils";
import { DEFAULT_NONCE_LENGTH } from "#/constants";
import type { Did } from "#/core/did/types";
import { base64UrlEncode } from "#/core/encoding";
import type { Signer } from "#/core/signer";
import { decodeBase64Url, serializeBase64Url } from "#/nuc/codec";
import { computeHash, type Envelope, type Nuc } from "#/nuc/envelope";
import {
  type Command,
  type DelegationPayload,
  isDelegationPayload,
  type Payload,
} from "#/nuc/payload";
import type { Policy, PolicyRule } from "#/nuc/policy";

/**
 * Abstract base class for building NUC tokens.
 * Provides common functionality for both delegation and invocation tokens.
 * @internal
 */
abstract class AbstractBuilder {
  protected _issuer?: Did;
  protected _audience?: Did;
  protected _subject?: Did;
  protected _command?: Command;
  protected _expiresAt?: number;
  protected _notBefore?: number;
  protected _meta?: Record<string, unknown>;
  protected _nonce?: string;
  protected _proof?: Envelope;

  protected abstract _getPayloadData(issuer: Did): Payload;

  /**
   * Sets the intended recipient of the token.
   * @param aud - The DID of the intended audience
   * @returns This builder instance for method chaining
   */
  public audience(aud: Did): this {
    this._audience = aud;
    return this;
  }

  /**
   * Sets the subject of the token.
   * @param sub - The DID of the subject
   * @returns This builder instance for method chaining
   */
  public subject(sub: Did): this {
    this._subject = sub;
    return this;
  }

  /**
   * Sets the command that this token grants access to.
   * @param cmd - The command string (must start with "/")
   * @returns This builder instance for method chaining
   */
  public command(cmd: Command): this {
    this._command = cmd;
    return this;
  }

  /**
   * Sets the expiration time for the token.
   * @param date - Expiration time in epoch milliseconds
   * @returns This builder instance for method chaining
   */
  public expiresAt(date: number): this {
    this._expiresAt = date;
    return this;
  }

  /**
   * Sets the "not before" time for the token.
   * @param date - The earliest time the token is valid, in epoch milliseconds
   * @returns This builder instance for method chaining
   */
  public notBefore(date: number): this {
    this._notBefore = date;
    return this;
  }

  /**
   * Sets arbitrary metadata for the token.
   * @param meta - A record of key-value pairs
   * @returns This builder instance for method chaining
   */
  public meta(meta: Record<string, unknown>): this {
    this._meta = meta;
    return this;
  }

  /**
   * Sets a custom nonce for the token.
   * @param nonce - The nonce string (auto-generated if not provided)
   * @returns This builder instance for method chaining
   */
  public nonce(nonce: string): this {
    this._nonce = nonce;
    return this;
  }

  /**
   * Sets the proof envelope for creating a chained token.
   * @param proof - The previous token envelope to chain from
   * @returns This builder instance for method chaining
   */
  public proof(proof: Envelope): this {
    this._proof = proof;
    return this;
  }

  /**
   * Sets the issuer of the token.
   * @param iss - The DID of the issuer (defaults to the signing keypair's DID)
   * @returns This builder instance for method chaining
   */
  public issuer(iss: Did): this {
    this._issuer = iss;
    return this;
  }

  /**
   * Builds and signs the token with the provided signer.
   * @param signer - The signer to sign the token with
   * @returns The signed token envelope
   * @throws {Error} If required fields (audience, subject, command) are missing
   */
  public async build(signer: Signer): Promise<Envelope> {
    // The issuer is now authoritatively derived from the signer.
    const issuer = this._issuer ?? (await signer.getDid());
    const payloadData = this._getPayloadData(issuer);

    const header = signer.header;
    const rawHeader = base64UrlEncode(
      new TextEncoder().encode(JSON.stringify(header)),
    );

    const rawPayload = base64UrlEncode(
      new TextEncoder().encode(JSON.stringify(payloadData)),
    );

    const messageToSign = new TextEncoder().encode(
      `${rawHeader}.${rawPayload}`,
    );
    const signature = await signer.sign(messageToSign);

    const nuc: Nuc = {
      rawHeader,
      rawPayload,
      signature: new Uint8Array(signature),
      payload: payloadData,
    };

    return {
      nuc: nuc,
      proofs: this._proof ? [this._proof.nuc, ...this._proof.proofs] : [],
    };
  }

  /**
   * Builds, signs, and serializes the token into a base64url string.
   * This is a convenience method that combines `build` and `serializeBase64Url`.
   * @param signer - The signer to sign the token with
   * @returns The signed and serialized token string
   */
  public async signAndSerialize(signer: Signer): Promise<string> {
    const envelope = await this.build(signer);
    return serializeBase64Url(envelope);
  }
}

/**
 * Builder for creating delegation tokens with policies.
 * Delegation tokens grant capabilities to other DIDs based on policy rules.
 */
export class DelegationBuilder extends AbstractBuilder {
  private _policy: Policy = [];

  /**
   * Sets the complete policy array for the delegation.
   * @param policy - Array of policy rules
   * @returns This builder instance for method chaining
   */
  public policy(policy: Policy): this {
    this._policy = policy;
    return this;
  }

  /**
   * Adds a single policy rule to the existing policy array.
   * @param policy - A policy rule tuple (e.g., ["==", ".command", "/db/read"])
   * @returns This builder instance for method chaining
   */
  public addPolicy(policy: PolicyRule): this {
    this._policy.push(policy);
    return this;
  }

  protected _getPayloadData(issuer: Did): DelegationPayload {
    if (!this._audience || !this._subject || !this._command) {
      throw new Error("Audience, subject, and command are required fields.");
    }

    return {
      iss: issuer,
      aud: this._audience,
      sub: this._subject,
      cmd: this._command,
      pol: this._policy,
      nbf: this._notBefore,
      exp: this._expiresAt,
      meta: this._meta,
      nonce: this._nonce || bytesToHex(randomBytes(DEFAULT_NONCE_LENGTH)),
      prf: this._proof ? [bytesToHex(computeHash(this._proof.nuc))] : [],
    };
  }
}

/**
 * Builder for creating invocation tokens with arguments.
 * Invocation tokens execute specific commands with provided arguments.
 */
export class InvocationBuilder extends AbstractBuilder {
  private _args: Record<string, unknown> = {};

  /**
   * Sets all arguments for the invocation at once.
   * @param args - Record of argument key-value pairs
   * @returns This builder instance for method chaining
   */
  public arguments(args: Record<string, unknown>): this {
    this._args = args;
    return this;
  }

  /**
   * Adds or updates a single argument.
   * @param key - The argument key
   * @param value - The argument value
   * @returns This builder instance for method chaining
   */
  public addArgument(key: string, value: unknown): this {
    this._args[key] = value;
    return this;
  }

  protected _getPayloadData(issuer: Did): Payload {
    if (!this._audience || !this._subject || !this._command) {
      throw new Error("Audience, subject, and command are required fields.");
    }

    return {
      iss: issuer,
      aud: this._audience,
      sub: this._subject,
      cmd: this._command,
      args: this._args,
      nbf: this._notBefore,
      exp: this._expiresAt,
      meta: this._meta,
      nonce: this._nonce || bytesToHex(randomBytes(DEFAULT_NONCE_LENGTH)),
      prf: this._proof ? [bytesToHex(computeHash(this._proof.nuc))] : [],
    };
  }
}

/**
 * Factory object for creating NUC token builders.
 * Provides fluent API entry points for creating delegation and invocation tokens.
 *
 * @example
 * ```typescript
 * import { Builder } from "#/nuc/builder";
 * import { Signers } from "#/core/signer";
 * import { Keypair } from "#/core/keypair";
 *
 * const keypair = Keypair.generate();
 * const signer = Signers.fromKeypair(keypair);
 *
 * // Create a delegation token
 * const delegation = Builder.delegation()
 *   .audience(audienceDid)
 *   .subject(subjectDid)
 *   .command("/db/read")
 *   .policy([["==", ".command", "/db/read"]])
 *   .build(keypair);
 *
 * // Create an invocation token from the delegation
 * const invocation = Builder.invoking(delegation)
 *   .audience(audienceDid)
 *   .arguments({ table: "users", id: 123 })
 *   .build(await Signers.fromKeypair(userKeypair));
 * ```
 */
export const Builder = {
  /**
   * Creates a new DelegationBuilder for building delegation tokens.
   * @returns A new DelegationBuilder instance
   * @example
   * ```typescript
   * const token = Builder.delegation()
   *   .audience(audienceDid)
   *   .subject(subjectDid)
   *   .command("/db/read")
   *   .policy([["==", ".command", "/db/read"]])
   *   .build(signer);
   * ```
   */
  delegation(): DelegationBuilder {
    return new DelegationBuilder();
  },

  /**
   * Creates a new InvocationBuilder for building invocation tokens.
   * @returns A new InvocationBuilder instance
   * @example
   * ```typescript
   * const token = Builder.invocation()
   *   .audience(audienceDid)
   *   .subject(subjectDid)
   *   .command("/db/execute")
   *   .arguments({ query: "SELECT * FROM users" })
   *   .build(signer);
   * ```
   */
  invocation(): InvocationBuilder {
    return new InvocationBuilder();
  },

  /**
   * Creates a DelegationBuilder pre-configured from an existing delegation token.
   * Used for creating chained delegation tokens.
   * @param proof - The existing delegation token envelope to extend
   * @returns A pre-configured DelegationBuilder
   * @throws {Error} If the proof token is not a delegation
   * @example
   * ```typescript
   * const rootToken = Builder.delegation()
   *   .audience(userDid)
   *   .subject(userDid)
   *   .command("/db/read")
   *   .policy([["==", ".command", "/db/read"]])
   *   .build(await Signers.fromKeypair(rootKeypair));
   *
   * const chainedToken = Builder.delegating(rootToken)
   *   .audience(newAudience) // Override the audience
   *   .build(await Signers.fromKeypair(userKeypair));
   * ```
   */
  delegating(proof: Envelope): DelegationBuilder {
    const proofPayload = proof.nuc.payload;
    if (!isDelegationPayload(proofPayload)) {
      throw new Error("Cannot extend a token that is not a delegation.");
    }

    const builder = new DelegationBuilder();
    builder.subject(proofPayload.sub);
    builder.command(proofPayload.cmd);
    builder.proof(proof);
    builder.policy(proofPayload.pol);

    return builder;
  },

  /**
   * Creates an InvocationBuilder pre-configured from a delegation token.
   * Used for invoking capabilities granted by a delegation.
   * @param proof - The delegation token envelope granting the capability
   * @returns A pre-configured InvocationBuilder
   * @throws {Error} If the proof token is not a delegation
   * @example
   * ```typescript
   * const delegationToken = Builder.delegation()
   *   .audience(userDid)
   *   .subject(userDid)
   *   .command("/db/read")
   *   .policy([["==", ".command", "/db/read"]])
   *   .build(await Signers.fromKeypair(rootKeypair));
   *
   * const invocationToken = Builder.invoking(delegationToken)
   *   .audience(serviceDid)
   *   .arguments({ table: "users" })
   *   .build(await Signers.fromKeypair(userKeypair));
   * ```
   */
  invoking(proof: Envelope): InvocationBuilder {
    const proofPayload = proof.nuc.payload;
    if (!isDelegationPayload(proofPayload)) {
      throw new Error(
        "Cannot invoke a capability from a token that is not a delegation.",
      );
    }

    const builder = new InvocationBuilder();
    builder.subject(proofPayload.sub);
    builder.command(proofPayload.cmd);
    builder.proof(proof);

    return builder;
  },

  /**
   * Creates a DelegationBuilder pre-configured from an existing serialized delegation token string.
   * @param proofString - The base64url encoded string of the delegation to extend
   * @returns A pre-configured DelegationBuilder
   */
  delegatingFromString(proofString: string): DelegationBuilder {
    const proof = decodeBase64Url(proofString);
    return this.delegating(proof);
  },

  /**
   * Creates an InvocationBuilder pre-configured from a serialized delegation token string.
   * @param proofString - The base64url encoded string of the delegation to invoke
   * @returns A pre-configured InvocationBuilder
   */
  invokingFromString(proofString: string): InvocationBuilder {
    const proof = decodeBase64Url(proofString);
    return this.invoking(proof);
  },
} as const;
