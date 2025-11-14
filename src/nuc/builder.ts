import { bytesToHex, randomBytes } from "@noble/hashes/utils.js";
import { DEFAULT_MAX_LIFETIME_MS, DEFAULT_NONCE_LENGTH } from "#/constants";
import type { Did } from "#/core/did/types";
import { base64UrlEncode } from "#/core/encoding";
import type { Signer } from "#/core/signer";
import { Codec } from "#/nuc/codec";
import { Envelope, type Nuc } from "#/nuc/envelope";
import { getEip712Header, NucHeaderType } from "#/nuc/header";
import { type Command, type DelegationPayload, Payload } from "#/nuc/payload";
import type { Policy, PolicyRule } from "#/nuc/policy";

/**
 * `Nuc` token builder base class.
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
  protected _maxLifetimeMs: number = DEFAULT_MAX_LIFETIME_MS;

  protected abstract _getPayloadData(issuer: Did): Payload;

  /**
   * Specifies the token's audience (aud), the recipient of the grant.
   *
   * The audience is the principal that this token is intended for and
   * who is authorised to use it. In a delegation chain, the audience of
   * one token becomes the issuer of the next.
   *
   * @param aud The recipient's Did.
   * @returns This builder for method chaining.
   */
  public audience(aud: Did): this {
    this._audience = aud;
    return this;
  }

  /**
   * Specifies the token's subject (sub), the principal the token is about.
   *
   * The subject is the principal whose authority is being delegated or invoked.
   * This claim must remain consistent throughout a delegation chain.
   *
   * @param sub The subject's Did.
   * @returns This builder for method chaining.
   */
  public subject(sub: Did): this {
    this._subject = sub;
    return this;
  }

  /**
   * Specifies the command this token authorizes.
   * @param cmd The command string.
   * @returns This builder for method chaining.
   */
  public command(cmd: Command): this {
    this._command = cmd;
    return this;
  }

  /**
   * Specifies when the token expires.
   *
   * After this time, the token will be rejected during validation.
   * Use epoch milliseconds for the expiration timestamp.
   *
   * @param date - Expiration time in epoch milliseconds
   * @returns This builder instance for method chaining
   * @example
   * ```typescript
   * builder.expiresAt(Date.now() + 3600 * 1000); // Expires in 1 hour
   * ```
   */
  public expiresAt(date: number): this {
    this._expiresAt = date;
    return this;
  }

  /**
   * Specifies the token's expiration as a duration from now.
   *
   * @param ms - The number of milliseconds from now when the token should expire.
   * @returns This builder instance for method chaining.
   * @example
   * ```typescript
   * builder.expiresIn(3600 * 1000); // Expires in 1 hour
   * ```
   */
  public expiresIn(ms: number): this {
    this._expiresAt = Date.now() + ms;
    return this;
  }

  /**
   * Specifies the earliest time the token becomes valid.
   *
   * The token will be rejected if used before this time.
   * Useful for scheduling future access.
   *
   * @param date - The earliest validity time in epoch milliseconds
   * @returns This builder instance for method chaining
   * @example
   * ```typescript
   * builder.notBefore(Date.now() + 60 * 1000); // Valid after 1 minute
   * ```
   */
  public notBefore(date: number): this {
    this._notBefore = date;
    return this;
  }

  /**
   * Attaches arbitrary metadata to the token.
   *
   * Metadata is not validated and can contain any JSON-serializable
   * data for application-specific purposes.
   *
   * @param meta - A record of key-value pairs
   * @returns This builder instance for method chaining
   * @example
   * ```typescript
   * builder.meta({
   *   requestId: "abc123",
   *   environment: "production",
   *   version: "1.0.0"
   * });
   * ```
   */
  public meta(meta: Record<string, unknown>): this {
    this._meta = meta;
    return this;
  }

  /**
   * Specifies a custom nonce for the token.
   *
   * Nonces provide uniqueness and prevent replay attacks.
   * If not specified, a cryptographically secure random nonce is generated.
   *
   * @param nonce - The nonce string
   * @returns This builder instance for method chaining
   * @example
   * ```typescript
   * builder.nonce("unique-nonce-123");
   * ```
   */
  public nonce(nonce: string): this {
    this._nonce = nonce;
    return this;
  }

  /**
   * Sets the maximum lifetime for the token being built.
   *
   * This value cannot exceed the default maximum lifetime or the remaining
   * lifetime of a parent proof token.
   *
   * @param ms - The maximum lifetime in milliseconds.
   * @returns This builder instance for method chaining.
   * @throws {Error} If the provided lifetime exceeds the allowed maximum.
   */
  public maxLifetime(ms: number): this {
    if (ms > this._maxLifetimeMs) {
      throw new Error(
        `Custom max lifetime of ${ms}ms exceeds the allowed maximum of ${this._maxLifetimeMs}ms.`,
      );
    }
    this._maxLifetimeMs = ms;
    return this;
  }

  /**
   * Links this token to a previous token in a delegation chain.
   *
   * The proof establishes the authority for this token based on
   * a previously issued delegation.
   *
   * @param proof - The previous token envelope to chain from
   * @returns This builder instance for method chaining
   * @example
   * ```typescript
   * builder.proof(previousDelegationEnvelope);
   * ```
   */
  public proof(proof: Envelope): this {
    this._proof = proof;
    return this;
  }

  /**
   * Specifies the token's issuer (iss), the principal who creates and signs the token.
   *
   * By default, the issuer is derived from the `Signer`'s Did during the build process.
   * Use this method only in advanced scenarios where the issuer needs to be explicitly
   * set to a Did other than the signer's.
   *
   * @param iss - The Did of the issuer
   * @returns This builder instance for method chaining
   * @example
   * ```typescript
   * builder.issuer(customIssuerDid);
   * ```
   */
  public issuer(iss: Did): this {
    this._issuer = iss;
    return this;
  }

  /**
   * Builds and signs the token with the provided signer.
   *
   * Validates that all required fields are present, generates the token
   * payload, and produces a signed envelope ready for transmission.
   *
   * @param signer - The signer to sign the token with
   * @returns The signed token envelope
   * @throws {Error} "Audience, subject, and command are required fields" - If any required field is missing
   * @example
   * ```typescript
   * const envelope = await builder
   *   .audience(audienceDid)
   *   .subject(subjectDid)
   *   .command("/db/read")
   *   .build(signer);
   * ```
   */
  public async sign(signer: Signer): Promise<Envelope> {
    // Validate expiration properties before signing.
    if (!this._expiresAt) {
      throw new Error(
        "Expiration is a required field. Use `expiresAt(timestamp)` or `expiresIn(duration)`.",
      );
    }
    if (this._expiresAt <= Date.now()) {
      throw new Error("Expiration date must be in the future.");
    }
    const maxExpiry = Date.now() + this._maxLifetimeMs;
    if (this._expiresAt > maxExpiry) {
      const asConfigured = new Date(this._expiresAt).toISOString();
      const maxAllowed = new Date(maxExpiry).toISOString();
      throw new Error(
        `Expiration of ${asConfigured} exceeds the maximum lifetime. Max expiry is ${maxAllowed}.`,
      );
    }

    // The issuer is now authoritatively derived from the signer.
    const issuer = this._issuer ?? (await signer.getDid());
    const payloadData = this._getPayloadData(issuer);

    // Generate the correct EIP-712 header based on payload type.
    const header =
      signer.header.typ === NucHeaderType.EIP712
        ? getEip712Header(payloadData)
        : signer.header;

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
   *
   * Convenience method that combines building and serialization
   * in a single step for easier token generation.
   *
   * @param signer - The signer to sign the token with
   * @returns The signed and serialized token string
   * @throws {Error} "Audience, subject, and command are required fields" - If any required field is missing
   * @example
   * ```typescript
   * const tokenString = await builder
   *   .audience(audienceDid)
   *   .subject(subjectDid)
   *   .command("/db/read")
   *   .signAndSerialize(signer);
   * ```
   * @see {@link sign}
   * @see {@link Codec.serializeBase64Url}
   */
  public async signAndSerialize(signer: Signer): Promise<string> {
    const envelope = await this.sign(signer);
    return Codec.serializeBase64Url(envelope);
  }
}

/**
 * Builds delegation tokens that grant capabilities to other DIDs.
 *
 * Delegation tokens establish trust relationships and permission boundaries
 * through policy rules that constrain how granted capabilities can be used.
 *
 * @example
 * ```typescript
 * const token = new DelegationBuilder()
 *   .audience(userDid)
 *   .subject(userDid)
 *   .command("/db/read")
 *   .policy([["==", ".command", "/db/read"]])
 *   .build(signer);
 * ```
 */
export class DelegationBuilder extends AbstractBuilder {
  private _policy: Policy = [];

  /**
   * Replaces all policies with the provided policy array.
   *
   * Policies define constraints that must be satisfied when the delegation
   * is used to create invocation tokens.
   *
   * @param policy - Array of policy rules to enforce
   * @returns This builder instance for method chaining
   * @example
   * ```typescript
   * builder.policy([
   *   ["==", ".command", "/db/read"],
   *   ["!=", ".args.table", "secrets"]
   * ]);
   * ```
   */
  public policy(policy: Policy): this {
    this._policy = policy;
    return this;
  }

  /**
   * Appends a single policy rule to the existing policy array.
   *
   * Use this method to incrementally build up policies instead of
   * replacing them all at once.
   *
   * @param policy - A policy rule tuple to add
   * @returns This builder instance for method chaining
   * @example
   * ```typescript
   * builder
   *   .addPolicy(["==", ".command", "/db/read"])
   *   .addPolicy(["!=", ".args.table", "secrets"]);
   * ```
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
      nbf: this._notBefore ? Math.floor(this._notBefore / 1000) : undefined,
      exp: this._expiresAt ? Math.floor(this._expiresAt / 1000) : undefined,
      meta: this._meta,
      nonce: this._nonce || bytesToHex(randomBytes(DEFAULT_NONCE_LENGTH)),
      prf: this._proof
        ? [bytesToHex(Envelope.computeHash(this._proof.nuc))]
        : [],
    };
  }
}

/**
 * Builds invocation tokens that execute commands with arguments.
 *
 * Invocation tokens represent the actual execution of a capability
 * that was granted by a delegation token. They carry the command
 * arguments and are validated against the delegation's policies.
 *
 * @example
 * ```typescript
 * const token = new InvocationBuilder()
 *   .audience(serviceDid)
 *   .subject(userDid)
 *   .command("/db/query")
 *   .arguments({ table: "users", limit: 100 })
 *   .build(signer);
 * ```
 */
export class InvocationBuilder extends AbstractBuilder {
  private _args: Record<string, unknown> = {};

  /**
   * Replaces all arguments with the provided record.
   *
   * Arguments are passed to the command when the invocation is executed.
   * These arguments are evaluated against policies in the delegation chain.
   *
   * @param args - Record of argument key-value pairs
   * @returns This builder instance for method chaining
   * @example
   * ```typescript
   * builder.arguments({
   *   table: "users",
   *   filter: { age: { $gte: 18 } },
   *   limit: 100
   * });
   * ```
   */
  public arguments(args: Record<string, unknown>): this {
    this._args = args;
    return this;
  }

  /**
   * Adds or updates a single argument in the arguments record.
   *
   * Use this method to incrementally build arguments or update
   * specific values without replacing the entire arguments object.
   *
   * @param key - The argument key to add or update
   * @param value - The argument value
   * @returns This builder instance for method chaining
   * @example
   * ```typescript
   * builder
   *   .addArgument("table", "users")
   *   .addArgument("limit", 100);
   * ```
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
      nbf: this._notBefore ? Math.floor(this._notBefore / 1000) : undefined,
      exp: this._expiresAt ? Math.floor(this._expiresAt / 1000) : undefined,
      meta: this._meta,
      nonce: this._nonce || bytesToHex(randomBytes(DEFAULT_NONCE_LENGTH)),
      prf: this._proof
        ? [bytesToHex(Envelope.computeHash(this._proof.nuc))]
        : [],
    };
  }
}

/**
 * Creates NUC token builders for constructing delegation and invocation tokens.
 *
 * This factory provides the primary API for token creation in the NUC system.
 * Use it to create builders for different token types and chain tokens together.
 *
 * @example
 * ```typescript
 * import { Builder, Signer } from "@nillion/nuc";
 *
 * const signer = Signer.generate();
 * const userSigner = Signer.generate();
 *
 * // Create a delegation token
 * const delegation = await Builder.delegation()
 *   .audience(audienceDid)
 *   .subject(subjectDid)
 *   .command("/db/read")
 *   .policy([["==", ".command", "/db/read"]])
 *   .sign(signer);
 *
 * // Create an invocation token from the delegation
 * const invocation = await Builder.invocationFrom(delegation)
 *   .audience(serviceDid)
 *   .arguments({ table: "users", id: 123 })
 *   .sign(userSigner);
 * ```
 */
export const Builder = {
  /**
   * Creates a new builder for constructing delegation tokens.
   *
   * Delegation tokens grant capabilities that can be further delegated
   * or invoked by the audience.
   *
   * @returns A new DelegationBuilder instance
   * @example
   * ```typescript
   * const token = await Builder.delegation()
   *   .audience(audienceDid)
   *   .subject(subjectDid)
   *   .command("/db/read")
   *   .policy([["==", ".command", "/db/read"]])
   *   .build(signer);
   * ```
   * @see {@link DelegationBuilder}
   */
  delegation(): DelegationBuilder {
    return new DelegationBuilder();
  },

  /**
   * Creates a new builder for constructing invocation tokens.
   *
   * Invocation tokens execute commands and are typically created
   * from existing delegations using `invoking()` instead.
   *
   * @returns A new InvocationBuilder instance
   * @example
   * ```typescript
   * const token = await Builder.invocation()
   *   .audience(serviceDid)
   *   .subject(subjectDid)
   *   .command("/db/execute")
   *   .arguments({ query: "SELECT * FROM users" })
   *   .build(signer);
   * ```
   * @see {@link InvocationBuilder}
   */
  invocation(): InvocationBuilder {
    return new InvocationBuilder();
  },

  /**
   * Creates a delegation builder pre-configured from an existing delegation.
   *
   * This creates a new `DelegationBuilder` that inherits the subject and
   * command from the provided proof envelope.
   *
   * @param proof - The existing delegation token envelope to extend from.
   * @returns A pre-configured DelegationBuilder.
   * @throws {Error} "Cannot create a delegation from a proof that is not a delegation" - If the proof is an invocation token
   * @example
   * ```typescript
   * const rootToken = await Builder.delegation()
   *   .audience(userDid)
   *   .subject(userDid)
   *   .command("/db/read")
   *   .policy([["==", ".command", "/db/read"]])
   *   .build(rootSigner);
   *
   * const chainedToken = await Builder.delegationFrom(rootToken)
   *   .audience(newAudience) // Override the audience
   *   .build(userSigner);
   * ```
   * @see {@link DelegationBuilder}
   */
  delegationFrom(proof: Envelope): DelegationBuilder {
    const proofPayload = proof.nuc.payload;
    if (!Payload.isDelegationPayload(proofPayload)) {
      throw new Error(
        "Cannot create a delegation from a proof that is not a delegation.",
      );
    }

    const builder = new DelegationBuilder();
    builder.subject(proofPayload.sub);
    builder.command(proofPayload.cmd);
    builder.proof(proof);

    // Cap the new token's lifetime by its parent's remaining validity.
    if (proofPayload.exp) {
      const remainingLifetimeMs = proofPayload.exp * 1000 - Date.now();
      if (remainingLifetimeMs <= 0) {
        throw new Error("Cannot create a chained token from an expired proof.");
      }
      builder.maxLifetime(remainingLifetimeMs);
    }

    return builder;
  },

  /**
   * Creates an invocation builder from a delegation token.
   *
   * This creates a new `InvocationBuilder` that inherits the subject and
   * command from the provided proof envelope.
   *
   * @param proof - The delegation token envelope granting the capability.
   * @returns A pre-configured InvocationBuilder.
   * @throws {Error} "Cannot invoke a capability from a proof that is not a delegation" - If the proof is not a delegation
   * @example
   * ```typescript
   * const delegationToken = await Builder.delegation()
   *   .audience(userDid)
   *   .subject(userDid)
   *   .command("/db/read")
   *   .policy([["==", ".command", "/db/read"]])
   *   .build(rootKeypair);
   *
   * const invocationToken = await Builder.invocationFrom(delegationToken)
   *   .audience(serviceDid)
   *   .arguments({ table: "users" })
   *   .build(userKeypair);
   * ```
   * @see {@link InvocationBuilder}
   */
  invocationFrom(proof: Envelope): InvocationBuilder {
    const proofPayload = proof.nuc.payload;
    if (!Payload.isDelegationPayload(proofPayload)) {
      throw new Error(
        "Cannot invoke a capability from a proof that is not a delegation.",
      );
    }

    const builder = new InvocationBuilder();
    builder.subject(proofPayload.sub);
    builder.command(proofPayload.cmd);
    builder.proof(proof);

    // Cap the new token's lifetime by its parent's remaining validity.
    if (proofPayload.exp) {
      const remainingLifetimeMs = proofPayload.exp * 1000 - Date.now();
      if (remainingLifetimeMs <= 0) {
        throw new Error("Cannot create a chained token from an expired proof.");
      }
      builder.maxLifetime(remainingLifetimeMs);
    }

    return builder;
  },

  /**
   * Creates a delegation builder from a serialized token string.
   * @param proofString - The base64url encoded delegation token string.
   * @returns A pre-configured DelegationBuilder.
   * @throws {Error} Decoding errors from {@link Codec.decodeBase64Url}
   * @throws {Error} "Cannot create a delegation from a proof that is not a delegation" - If decoded token is not a delegation
   * @example
   * ```typescript
   * const chainedToken = await Builder.delegationFromString(tokenString)
   *   .audience(newAudience)
   *   .build(signer);
   * ```
   */
  delegationFromString(proofString: string): DelegationBuilder {
    const proof = Codec.decodeBase64Url(proofString);
    return this.delegationFrom(proof);
  },

  /**
   * Creates an invocation builder from a serialized token string.
   * @param proofString - The base64url encoded delegation token string.
   * @returns A pre-configured InvocationBuilder.
   * @throws {Error} Decoding errors from {@link Codec.decodeBase64Url}
   * @throws {Error} "Cannot invoke a capability from a proof that is not a delegation" - If decoded token is not a delegation
   * @example
   * ```typescript
   * const invocation = await Builder.invocationFromString(tokenString)
   *   .audience(serviceDid)
   *   .arguments({ action: "read" })
   *   .build(signer);
   * ```
   */
  invocationFromString(proofString: string): InvocationBuilder {
    const proof = Codec.decodeBase64Url(proofString);
    return this.invocationFrom(proof);
  },
} as const;
