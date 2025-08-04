import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex, randomBytes } from "@noble/hashes/utils";
import ky, { HTTPError, type Options } from "ky";
import { z } from "zod";
import { DEFAULT_NONCE_LENGTH } from "#/constants";
import * as did from "#/core/did/did";
import { textToHex } from "#/core/encoding";
import {
  NilauthErrorCodeSchema,
  NilauthErrorResponse,
  NilauthErrorResponseBodySchema,
  NilauthUnreachable,
  PaymentTxFailed,
} from "#/core/errors";
import type { Keypair } from "#/core/keypair";
import { Log } from "#/core/logger";
import { Signers } from "#/core/signer";
import { Builder } from "#/nuc/builder";
import { serializeBase64Url } from "#/nuc/codec";
import type { Envelope } from "#/nuc/envelope";
import { computeHash } from "#/nuc/envelope";
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
  type ValidatePaymentResponse,
  ValidatePaymentResponseSchema,
} from "#/services/nilauth/types";
import { NilauthUrl } from "#/services/nilauth/urls";
import type { Payer } from "#/services/payer/client";

export type BlindModule = "nilai" | "nildb";

/**
 * Performs a request and handles standardized logging, parsing, and error handling.
 * @internal
 *
 *
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

function createSignedRequest(
  payload: Record<string, unknown>,
  keypair: Keypair,
) {
  const stringifiedPayload = JSON.stringify(payload);
  return {
    public_key: keypair.publicKey(),
    signature: keypair.sign(stringifiedPayload),
    payload: textToHex(stringifiedPayload),
  };
}

/**
 * Options required to construct a NilauthClient.
 */
export type NilauthClientOptions = {
  payer: Payer;
  nilauth: {
    baseUrl: string;
    publicKey: string;
  };
};

/**
 * Client for interacting with the Nilauth service.
 * Provides methods for token creation, validation, revocation, and subscription management.
 */
export class NilauthClient {
  /**
   * Creates a NilauthClient instance by automatically fetching the service's public key.
   * @param baseUrl - The base URL of the Nilauth service
   * @param payer - The Payer instance for handling payments
   * @returns A configured NilauthClient instance
   * @throws {NilauthUnreachable} If the service cannot be reached
   * @throws {z.ZodError} If the service response is invalid
   */
  static async create(baseUrl: string, payer: Payer): Promise<NilauthClient> {
    const url = NilauthUrl.about(baseUrl);
    const about = await performRequest(url, NilauthAboutResponseSchema);
    return new NilauthClient({
      payer,
      nilauth: {
        baseUrl,
        publicKey: about.publicKey,
      },
    });
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
        bytesToHex(computeHash(t)),
      ),
    };
    return performRequest(url, LookupRevokedTokenResponseSchema, {
      method: "POST",
      json,
    });
  }

  readonly #options: NilauthClientOptions;

  private constructor(options: NilauthClientOptions) {
    this.#options = options;
  }

  get payer(): Payer {
    return this.#options.payer;
  }

  get nilauthPublicKey(): string {
    return this.#options.nilauth.publicKey;
  }

  get nilauthBaseUrl(): string {
    return this.#options.nilauth.baseUrl;
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
   * Checks the subscription status for a public key and blind module.
   * @param publicKey - The public key to check subscription for
   * @param blindModule - The module to check subscription for ("nilai" or "nildb")
   * @returns Subscription status information
   * @throws {NilauthErrorResponse} If an unexpected error occurs (NOT_SUBSCRIBED errors are handled gracefully)
   */
  async subscriptionStatus(
    publicKey: string,
    blindModule: BlindModule,
  ): Promise<SubscriptionStatusResponse> {
    const url = NilauthUrl.subscriptions.status(
      this.nilauthBaseUrl,
      publicKey,
      blindModule,
    );
    try {
      return await performRequest(url, SubscriptionStatusResponseSchema);
    } catch (error) {
      if (error instanceof NilauthErrorResponse) {
        if (
          error.code === NilauthErrorCodeSchema.enum.NOT_SUBSCRIBED ||
          error.code === NilauthErrorCodeSchema.enum.TRANSACTION_LOOKUP
        ) {
          return { subscribed: false, details: null };
        }
      }
      throw error;
    }
  }

  /**
   * Performs a subscription payment and validates it with the service.
   * @param publicKey - The public key to subscribe
   * @param blindModule - The module to subscribe to ("nilai" or "nildb")
   * @throws {PaymentTxFailed} If the payment transaction fails
   * @throws {NilauthErrorResponse} If validation fails
   */
  async payAndValidate(publicKey: string, blindModule: BlindModule) {
    const cost = await this.subscriptionCost(blindModule);
    const { txHash, payloadHex } = await this.pay(cost, blindModule);
    await this.validatePayment({ publicKey, txHash, payloadHex });
    Log.info({ publicKey, blindModule }, "Subscription payment validated");
  }

  /**
   * Makes a payment for a subscription.
   * @param amount - The amount to pay
   * @param blindModule - The module being subscribed to
   * @returns The transaction hash and signed payload
   * @throws {PaymentTxFailed} If the payment transaction fails
   */
  async pay(
    amount: number,
    blindModule: BlindModule,
  ): Promise<{ txHash: string; payloadHex: string }> {
    const payload = JSON.stringify({
      nonce: bytesToHex(randomBytes(DEFAULT_NONCE_LENGTH)),
      service_public_key: this.nilauthPublicKey,
      blind_module: blindModule,
    });
    const payloadHex = textToHex(payload);
    const payloadDigest = sha256(payload);
    Log.debug(
      `Making payment with payload=${payloadHex}, digest=${bytesToHex(
        payloadDigest,
      )}`,
    );

    try {
      const txHash = await this.payer.pay(sha256(payload), amount);
      return { txHash, payloadHex };
    } catch (cause) {
      throw new PaymentTxFailed(cause);
    }
  }

  /**
   * Validates a payment with the Nilauth service.
   * @param config - Payment validation configuration
   * @param config.publicKey - The public key that made the payment
   * @param config.txHash - The transaction hash from the payment
   * @param config.payloadHex - The hex-encoded payment payload
   * @returns Payment validation response
   * @throws {NilauthErrorResponse} If validation fails
   * @remarks This endpoint has built-in retry logic (3 attempts with exponential backoff)
   * to handle potential transaction propagation delays on the blockchain.
   */
  async validatePayment(config: {
    publicKey: string;
    txHash: string;
    payloadHex: string;
  }): Promise<ValidatePaymentResponse> {
    const url = NilauthUrl.payments.validate(this.nilauthBaseUrl);
    const json = {
      tx_hash: config.txHash,
      payload: config.payloadHex,
      public_key: config.publicKey,
    };

    return performRequest(url, ValidatePaymentResponseSchema, {
      method: "POST",
      json,
      retry: {
        limit: 3,
        methods: ["post"],
        delay: (attemptCount) => 0.2 * 2 ** attemptCount * 1000,
      },
    });
  }

  /**
   * Requests an authentication token from the Nilauth service.
   * @param keypair - The keypair to sign the request with
   * @param blindModule - The module to request access for ("nilai" or "nildb")
   * @returns The created token response
   * @throws {NilauthErrorResponse} If token creation fails
   * @example
   * ```typescript
   * const keypair = Keypair.generate();
   * const response = await client.requestToken(keypair, "nildb");
   * const authToken = decodeBase64Url(response.nuc);
   * ```
   */
  requestToken(
    keypair: Keypair,
    blindModule: BlindModule,
  ): Promise<CreateTokenResponse> {
    const url = NilauthUrl.nucs.create(this.nilauthBaseUrl);
    const json = createSignedRequest(
      {
        nonce: bytesToHex(randomBytes(DEFAULT_NONCE_LENGTH)),
        target_public_key: this.nilauthPublicKey,
        expires_at: Math.floor((Date.now() + 60_000) / 1000),
        blind_module: blindModule,
      },
      keypair,
    );
    return performRequest(url, CreateTokenResponseSchema, {
      method: "POST",
      json,
    }).then((response) => {
      Log.info({ blindModule }, "Auth token successfully requested");
      return response;
    });
  }

  /**
   * Revokes a previously issued token.
   * @param config - Revocation configuration
   * @param config.keypair - The keypair to sign the revocation with
   * @param config.authToken - The authentication token granting revocation permission
   * @param config.tokenToRevoke - The token to revoke
   * @throws {NilauthErrorResponse} If revocation fails
   * @example
   * ```typescript
   * await client.revokeToken({
   *   keypair: adminKeypair,
   *   authToken: adminAuthToken,
   *   tokenToRevoke: userToken
   * });
   * ```
   */
  async revokeToken(config: {
    keypair: Keypair;
    authToken: Envelope;
    tokenToRevoke: Envelope;
  }): Promise<void> {
    const { keypair, authToken, tokenToRevoke } = config;

    const revokeTokenEnvelope = await Builder.invocation()
      .arguments({
        token: serializeBase64Url(tokenToRevoke),
      })
      .command(REVOKE_COMMAND)
      .audience(did.parse(`did:nil:${this.nilauthPublicKey}`))
      .issuer(keypair.toDid("nil"))
      .subject(authToken.nuc.payload.sub)
      .proof(authToken)
      .build(Signers.fromLegacyKeypair(keypair));

    const revokeTokenString = serializeBase64Url(revokeTokenEnvelope);
    const url = NilauthUrl.nucs.revoke(this.nilauthBaseUrl);

    await performRequest(url, z.unknown(), {
      method: "POST",
      headers: { Authorization: `Bearer ${revokeTokenString}` },
    });

    Log.info(
      {
        revokedTokenHash: bytesToHex(computeHash(tokenToRevoke.nuc)),
      },
      "Token successfully revoked",
    );
  }
}
