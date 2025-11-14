import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, randomBytes } from "@noble/hashes/utils.js";
import ky, { HTTPError, type Options } from "ky";
import { z } from "zod";
import { ONE_MINUTE_MS } from "#/constants";
import { Did } from "#/core/did/did";
import {
  NilauthErrorResponse,
  NilauthErrorResponseBodySchema,
  NilauthUnreachable,
  PaymentTxFailed,
} from "#/core/errors";
import { Log } from "#/core/logger";
import type { Signer } from "#/core/signer";
import { Builder } from "#/nuc/builder";
import { Codec } from "#/nuc/codec";
import { Envelope } from "#/nuc/envelope";
import { REVOKE_COMMAND } from "#/nuc/payload";
import {
  type CreateTokenResponse,
  CreateTokenResponseSchema,
  type LookupRevokedTokenResponse,
  LookupRevokedTokenResponseSchema,
  type NilauthAboutResponse,
  NilauthAboutResponseSchema,
  type NilauthHealthResponse,
  NilauthHealthResponseSchema,
  type SubscriptionCostResponse,
  SubscriptionCostResponseSchema,
  type SubscriptionStatusResponse,
  SubscriptionStatusResponseSchema,
  ValidatePaymentResponseSchema,
} from "#/services/nilauth/types";
import { NilauthUrl } from "#/services/nilauth/urls";
import type { Payer } from "#/services/payer/client";

export type BlindModule = "nilai" | "nildb";

/**
 * Performs a request and handles standardized logging, parsing, and error handling.
 * @internal
 */
async function performRequest<T>(
  url: string,
  schema: z.ZodType<T>,
  options: Options = {},
): Promise<T> {
  const method = options.method?.toUpperCase() || "GET";
  Log.debug(`Request started: method=${method} url=${url}`);

  try {
    const response = await ky(url, options);
    const body = response.headers
      .get("content-type")
      ?.includes("application/json")
      ? await response.json()
      : await response.text();

    const result = schema.parse(body);
    Log.debug(`Request succeeded: method=${method} url=${url}`);
    return result;
  } catch (error) {
    Log.error(`Request failed: method=${method} url=${url} error=${error}`);

    if (error instanceof z.ZodError) {
      throw error;
    }

    if (error instanceof HTTPError) {
      try {
        const errorBody = await error.response.json();
        const parsedError = NilauthErrorResponseBodySchema.parse(errorBody);
        throw new NilauthErrorResponse(
          url,
          parsedError.error_code,
          parsedError.message,
          error.response.status,
          error,
        );
      } catch (_error) {
        // allow fall through to nilauth unreachable
      }
    }

    throw new NilauthUnreachable(url, error);
  }
}

/**
 * Options required to construct a NilauthClient.
 */
export type NilauthClientOptions = {
  payer?: Payer;
  nilauth: {
    baseUrl: string;
    publicKey: string;
    did: Did;
  };
};

/**
 * Client for interacting with the Nilauth service.
 * Provides methods for token creation, validation, revocation, and subscription management.
 */
export class NilauthClient {
  /**
   * Creates a NilauthClient instance by automatically fetching the service's public key.
   * @param options - An object containing the Nilauth's baseUrl and an optional payer
   * @returns A configured NilauthClient instance
   * @throws {NilauthUnreachable} If the service cannot be reached
   * @throws {z.ZodError} If the service response is invalid
   */
  static async create(options: {
    baseUrl: string;
    payer?: Payer;
  }): Promise<NilauthClient> {
    const { baseUrl, payer } = options;
    const url = NilauthUrl.about(baseUrl);
    const about = await performRequest(url, NilauthAboutResponseSchema);
    return new NilauthClient({
      payer,
      nilauth: {
        baseUrl,
        publicKey: about.publicKey,
        did: Did.fromPublicKey(about.publicKey, "key"),
      },
    });
  }

  readonly #options: NilauthClientOptions;

  private constructor(options: NilauthClientOptions) {
    this.#options = options;
  }

  get payer(): Payer | undefined {
    return this.#options.payer;
  }

  get nilauthPublicKey(): string {
    return this.#options.nilauth.publicKey;
  }

  get nilauthDid(): Did {
    return this.#options.nilauth.did;
  }

  get nilauthBaseUrl(): string {
    return this.#options.nilauth.baseUrl;
  }

  /**
   * Creates a self-signed identity NUC for authenticating a request.
   * @internal
   */
  private async createIdentityNuc(
    signer: Signer,
    command: string,
  ): Promise<string> {
    const subject = await signer.getDid();
    return Builder.invocation()
      .subject(subject)
      .audience(this.nilauthDid)
      .command(command)
      .expiresIn(ONE_MINUTE_MS)
      .signAndSerialize(signer);
  }

  /**
   * Fetches service metadata from the Nilauth server.
   * @returns Service information including version and public key
   * @throws {NilauthErrorResponse} If the service returns an error
   * @throws {NilauthUnreachable} If the service cannot be reached
   */
  about(): Promise<NilauthAboutResponse> {
    const url = NilauthUrl.about(this.nilauthBaseUrl);
    return performRequest(url, NilauthAboutResponseSchema);
  }

  /**
   * Performs a health check against a Nilauth server.
   * @param serviceUrl - The URL of the Nilauth service to check
   * @returns Health status information
   * @throws {NilauthUnreachable} If the service cannot be reached
   */
  static health(serviceUrl: string): Promise<NilauthHealthResponse> {
    const url = NilauthUrl.health(serviceUrl);
    return performRequest(url, NilauthHealthResponseSchema);
  }

  /**
   * Performs a health check against this client's Nilauth server.
   * @returns Health status information
   * @throws {NilauthUnreachable} If the service cannot be reached
   */
  health(): Promise<NilauthHealthResponse> {
    const url = NilauthUrl.health(this.nilauthBaseUrl);
    return performRequest(url, NilauthHealthResponseSchema);
  }

  /**
   * Queries the Nilauth server for any revoked tokens in the provided proof chain.
   * @param token - The token envelope containing the chain to check
   * @returns Information about any revoked tokens found in the chain
   * @throws {NilauthErrorResponse} If the service returns an error
   * @throws {NilauthUnreachable} If the service cannot be reached
   */
  findRevocationsInProofChain(
    token: Envelope,
  ): Promise<LookupRevokedTokenResponse> {
    const url = NilauthUrl.nucs.findRevocations(this.nilauthBaseUrl);
    const json = {
      hashes: [token.nuc, ...token.proofs].map((t) =>
        bytesToHex(Envelope.computeHash(t)),
      ),
    };
    return performRequest(url, LookupRevokedTokenResponseSchema, {
      method: "POST",
      json,
    });
  }

  /**
   * Gets the subscription cost for a specific blind module.
   * @param blindModule - The module to check pricing for ("nilai" or "nildb")
   * @returns The cost information for the subscription
   * @throws {NilauthErrorResponse} If the service returns an error
   */
  subscriptionCost(
    blindModule: BlindModule,
  ): Promise<SubscriptionCostResponse> {
    const url = NilauthUrl.payments.cost(this.nilauthBaseUrl, blindModule);
    return performRequest(url, SubscriptionCostResponseSchema);
  }

  /**
   * Checks the subscription status for a Did and blind module.
   * @param did - The Did to check subscription for
   * @param blindModule - The module to check subscription for ("nilai" or "nildb")
   * @returns Subscription status information
   * @throws {NilauthErrorResponse} If an unexpected error occurs
   */
  async subscriptionStatus(
    did: Did,
    blindModule: BlindModule,
  ): Promise<SubscriptionStatusResponse> {
    const url = NilauthUrl.subscriptions.status(
      this.nilauthBaseUrl,
      Did.serialize(did),
      blindModule,
    );
    return performRequest(url, SubscriptionStatusResponseSchema);
  }

  /**
   * Creates the payload for a subscription payment and its corresponding resource hash.
   * This is the first step in the decoupled payment flow. The returned `resourceHash`
   * is sent on-chain, and the `payload` object is used for validation.
   * @param subscriberDid - The Did of the identity receiving the subscription.
   * @param blindModule - The module to subscribe to ("nilai" or "nildb").
   * @param payerDid - The Did of the identity paying for the subscription.
   * @returns An object containing the payload and its SHA-256 hash.
   */
  createPaymentResource(
    subscriberDid: Did,
    blindModule: BlindModule,
    payerDid: Did,
  ): { resourceHash: Uint8Array; payload: object } {
    // Key ordering must match what nilauth expects. A more robust canonical JSON
    // serialization should be used in the future.
    // See: https://github.com/NillionNetwork/nilauth/issues/50
    const payload = {
      service_public_key: this.nilauthPublicKey,
      nonce: bytesToHex(randomBytes(16)),
      blind_module: blindModule,
      payer_did: Did.serialize(payerDid),
      subscriber_did: Did.serialize(subscriberDid),
    };

    const payloadStr = JSON.stringify(payload);
    const resourceHash = sha256(new TextEncoder().encode(payloadStr));
    Log.debug(
      `Created payment resource with payload=${payloadStr}, digest=${bytesToHex(
        resourceHash,
      )}`,
    );

    return { resourceHash, payload };
  }

  /**
   * Validates a payment transaction with the nilauth service.
   * This is the final step in the decoupled payment flow.
   * @param txHash - The transaction hash from the on-chain payment.
   * @param payload - The original payload object returned by `createPaymentResource`.
   * @param payerSigner - The signer of the identity that paid for the subscription.
   * @throws {NilauthErrorResponse} If payment validation fails.
   */
  async validatePayment(
    txHash: string,
    payload: object,
    payerSigner: Signer,
  ): Promise<void> {
    const identityNuc = await this.createIdentityNuc(
      payerSigner,
      "/nil/auth/payments/validate",
    );

    const url = NilauthUrl.payments.validate(this.nilauthBaseUrl);
    const json = {
      tx_hash: txHash,
      payload: payload,
    };

    await performRequest(url, ValidatePaymentResponseSchema, {
      method: "POST",
      json,
      headers: {
        Authorization: `Bearer ${identityNuc}`,
      },
      retry: {
        limit: 3,
        methods: ["post"],
        delay: (attemptCount) => 0.2 * 2 ** attemptCount * 1000,
      },
    });

    Log.info({ txHash }, "Subscription payment validated");
  }

  /**
   * Performs a subscription payment and validates it with the service.
   * @deprecated This method will be removed in a future version. Use the decoupled flow: `createPaymentResource`, `payer.pay`, and `validatePayment`.
   * @param payerSigner - The signer of the identity paying for the subscription.
   * @param subscriberDid - The Did of the identity receiving the subscription.
   * @param blindModule - The module to subscribe to ("nilai" or "nildb").
   * @throws {Error} If a Payer instance is not configured on the client.
   * @throws {PaymentTxFailed} If the on-chain payment transaction fails.
   * @throws {NilauthErrorResponse} If payment validation fails.
   */
  async payAndValidate(
    payerSigner: Signer,
    subscriberDid: Did,
    blindModule: BlindModule,
  ): Promise<void> {
    if (!this.payer) {
      throw new Error(
        "A Payer instance is required for this operation. Please provide it during NilauthClient creation.",
      );
    }

    const costUnil = await this.subscriptionCost(blindModule);
    const payerDid = await payerSigner.getDid();

    const { resourceHash, payload } = this.createPaymentResource(
      subscriberDid,
      blindModule,
      payerDid,
    );

    let txHash: string;
    try {
      txHash = await this.payer.pay(resourceHash, costUnil);
    } catch (cause) {
      throw new PaymentTxFailed(cause);
    }

    await this.validatePayment(txHash, payload, payerSigner);
  }

  /**
   * Requests a root NUC from the Nilauth service for an active subscription.
   * This must be performed by the **Subscriber**.
   * @param subscriberSigner - The signer of the subscribed identity.
   * @param blindModule - The module to request a token for ("nilai" or "nildb").
   * @returns The created token response.
   * @throws {NilauthErrorResponse} If token creation fails (e.g., no active subscription).
   */
  async requestToken(
    subscriberSigner: Signer,
    blindModule: BlindModule,
  ): Promise<CreateTokenResponse> {
    const identityNuc = await this.createIdentityNuc(
      subscriberSigner,
      "/nil/auth/nucs/create",
    );

    const url = NilauthUrl.nucs.create(this.nilauthBaseUrl);
    const json = { blind_module: blindModule };

    const response = await performRequest(url, CreateTokenResponseSchema, {
      method: "POST",
      json,
      headers: {
        Authorization: `Bearer ${identityNuc}`,
      },
    });

    Log.info({ blindModule }, "Root token successfully requested");
    return response;
  }

  /**
   * Revokes a previously issued token.
   * @param config - Revocation configuration
   * @param config.signer - The signer to authorize the revocation
   * @param config.authToken - The authentication token granting revocation permission
   * @param config.tokenToRevoke - The token to revoke
   * @throws {NilauthErrorResponse} If revocation fails
   */
  async revokeToken(config: {
    signer: Signer;
    authToken: Envelope;
    tokenToRevoke: Envelope;
  }): Promise<void> {
    const { signer, authToken, tokenToRevoke } = config;

    const issuer = await signer.getDid();

    // Calculate auth token's remaining lifetime
    const authTokenExp = authToken.nuc.payload.exp;
    const remainingLifetimeMs = (authTokenExp as number) * 1000 - Date.now();

    const revokeTokenEnvelope = await Builder.invocationFrom(authToken)
      .arguments({
        token: Codec.serializeBase64Url(tokenToRevoke),
      })
      .command(REVOKE_COMMAND)
      .audience(this.nilauthDid)
      .issuer(issuer)
      // Use most of parent's remaining lifetime (builder will cap if needed)
      .expiresIn(Math.min(ONE_MINUTE_MS, remainingLifetimeMs * 0.9))
      .sign(signer);

    const revokeTokenString = Codec.serializeBase64Url(revokeTokenEnvelope);
    const url = NilauthUrl.nucs.revoke(this.nilauthBaseUrl);

    await performRequest(url, z.unknown(), {
      method: "POST",
      headers: { Authorization: `Bearer ${revokeTokenString}` },
    });

    Log.info(
      {
        revokedTokenHash: bytesToHex(Envelope.computeHash(tokenToRevoke.nuc)),
      },
      "Token successfully revoked",
    );
  }
}
