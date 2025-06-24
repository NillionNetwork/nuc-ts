import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex } from "@noble/hashes/utils";
import { Duration as D, Effect as E, pipe, Schedule as S } from "effect";
import { Temporal } from "temporal-polyfill";
import type { ZodError } from "zod";
import { NucTokenBuilder } from "#/builder";
import type { NucTokenEnvelope } from "#/envelope";
import {
  type InvalidContentType,
  NilauthErrorCodeSchema,
  NilauthErrorResponse,
  PaymentTxFailed,
} from "#/errors";
import type { Keypair } from "#/keypair";
import { log } from "#/logger";
import {
  type FetchError,
  fetchWithTimeout,
  type RequestOptions,
} from "#/nilauth/retryable-fetch";
import {
  type CreateTokenResponse,
  CreateTokenResponseSchema,
  type LookupRevokedTokenResponse,
  LookupRevokedTokenResponseSchema,
  type NilauthAboutResponse,
  NilauthAboutResponseSchema,
  type NilauthHealthResponse,
  NilauthHealthResponseSchema,
  type PublicKey,
  type SubscriptionCostResponse,
  SubscriptionCostResponseSchema,
  type SubscriptionStatusResponse,
  SubscriptionStatusResponseSchema,
  type ValidatePaymentResponse,
  ValidatePaymentResponseSchema,
} from "#/nilauth/types";
import { NilauthUrl } from "#/nilauth/urls";
import type { Payer } from "#/payer/client";
import { Did, InvocationBody, REVOKE_COMMAND } from "#/token";
import {
  assertType,
  createSignedRequest,
  extractResponseJson,
  extractResponseText,
  generateNonce,
  type Hex,
  parseWithZodSchema,
  toHex,
  unwrapEffect,
} from "#/utils";

export type BlindModule = "nilai" | "nildb";

/**
 * Options required to construct a NilauthClient.
 */
export type NilauthClientOptions = {
  payer: Payer;
  nilauth: {
    baseUrl: string;
    publicKey: PublicKey;
  };
};

/**
 * Client for interacting with the Nilauth service.
 *
 * Provides methods for health checks, subscription management, payments,
 * token issuance, revocation, and proof chain validation.
 * Uses effectful, composable pipelines for all network operations with
 * consistent error handling and typed responses.
 */
export class NilauthClient {
  /**
   * Initialize a NilauthClient by automatically fetching the service's public key.
   *
   * @param baseUrl - The base URL of the Nilauth service.
   * @param payer - The payer instance used for handling subscription payments.
   * @returns Promise resolving to a fully configured NilauthClient instance.
   */
  static async from(baseUrl: string, payer: Payer): Promise<NilauthClient> {
    const about = await NilauthClient.about(baseUrl);
    return new NilauthClient({
      payer,
      nilauth: {
        baseUrl,
        publicKey: about.publicKey,
      },
    });
  }

  /**
   * Fetch service metadata from a Nilauth server.
   *
   * Retrieves information including the service's public key, start time, and build information.
   *
   * @param serviceUrl - The base URL of the Nilauth service.
   * @returns Promise resolving to the service metadata.
   */
  static about(serviceUrl: string): Promise<NilauthAboutResponse> {
    const url = NilauthUrl.about(serviceUrl);
    const request: RequestOptions = { url, method: "GET" };

    return pipe(
      fetchWithTimeout(request),
      extractResponseJson(),
      parseWithZodSchema(NilauthAboutResponseSchema),
      assertType<NilauthAboutResponse>(),
      logOutcome(request),
      unwrapEffect,
    );
  }

  /**
   * Perform a health check against a Nilauth server.
   *
   * Used to verify that the server is operational and responding to requests.
   *
   * @param serviceUrl - The base URL of the Nilauth service.
   * @returns Promise resolving to "OK" if the service is healthy.
   */
  static health(serviceUrl: string): Promise<NilauthHealthResponse> {
    const url = NilauthUrl.health(serviceUrl);
    const request: RequestOptions = { url, method: "GET" };

    return pipe(
      fetchWithTimeout(request),
      extractResponseText(),
      parseWithZodSchema(NilauthHealthResponseSchema),
      assertType<NilauthHealthResponse>(),
      logOutcome(request),
      unwrapEffect,
    );
  }

  /**
   * Queries a Nilauth server for any revoked tokens in the provided proof chain.
   *
   * This is a critical validation step in NUC verification. If any revocations are found,
   * the token should be considered invalid and rejected by any receiving entity.
   *
   * @param baseUrl - The base URL of the Nilauth service.
   * @param token - The token envelope containing the proof chain to validate.
   * @returns Promise resolving to a response containing any revoked tokens found.
   */
  static findRevocationsInProofChain(
    baseUrl: string,
    token: NucTokenEnvelope,
  ): Promise<LookupRevokedTokenResponse> {
    return unwrapEffect(
      NilauthClient.findRevocationsInProofChainEffect(baseUrl, token),
    );
  }

  /**
   * Effect-based implementation for querying revocations in a proof chain.
   *
   * Provides the same functionality as `findRevocationsInProofChain` but returns
   * an Effect that can be composed with other operations.
   *
   * @param baseUrl - The base URL of the Nilauth service.
   * @param token - The token envelope containing the proof chain to validate.
   * @returns Effect resolving to a response with revoked tokens or failing with typed errors.
   */
  static findRevocationsInProofChainEffect(
    baseUrl: string,
    token: NucTokenEnvelope,
  ): E.Effect<
    LookupRevokedTokenResponse,
    ZodError | InvalidContentType | FetchError
  > {
    const url = NilauthUrl.nucs.findRevocations(baseUrl);
    const body = {
      hashes: [token.token, ...token.proofs].map((token) =>
        bytesToHex(token.computeHash()),
      ),
    };
    const request: RequestOptions = {
      url,
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body,
    };

    return pipe(
      fetchWithTimeout(request),
      extractResponseJson(),
      parseWithZodSchema(LookupRevokedTokenResponseSchema),
      assertType<LookupRevokedTokenResponse>(),
      logOutcome(request),
    );
  }

  #options: NilauthClientOptions;

  /**
   * Construct a NilauthClient directly from configuration options.
   *
   * For most use cases, prefer using the static `from()` method which automatically
   * fetches the service's public key.
   *
   * @param options - Client configuration including keypair, payer, and nilauth service info.
   */
  constructor(options: NilauthClientOptions) {
    this.#options = options;
  }

  /**
   * The nilchain payer instance used for handling subscription payments.
   * Used internally during payment operations.
   */
  get payer(): Payer {
    return this.#options.payer;
  }

  /**
   * The Nilauth service's public key.
   * Used for verification and authentication.
   */
  get nilauthPublicKey(): string {
    return this.#options.nilauth.publicKey;
  }

  /**
   * The Nilauth service's base URL.
   * All API endpoints are constructed relative to this URL.
   */
  get nilauthBaseUrl(): string {
    return this.#options.nilauth.baseUrl;
  }

  /**
   * Retrieve server metadata from the configured Nilauth service.
   *
   * Returns information including the service's public key, start time,
   * and build details.
   *
   * @returns Promise resolving to the service metadata.
   */
  // biome-ignore lint/suspicious/useAdjacentOverloadSignatures: false positive
  about(): Promise<NilauthAboutResponse> {
    return NilauthClient.about(this.nilauthBaseUrl);
  }

  /**
   * Verify that the configured Nilauth service is operational.
   *
   * Performs a simple health check to confirm the server is responding.
   *
   * @returns Promise resolving to "OK" if the service is healthy.
   */
  health(): Promise<NilauthHealthResponse> {
    return NilauthClient.health(this.nilauthBaseUrl);
  }

  /**
   * Fetch the current subscription cost from the Nilauth service.
   *
   * Returns the cost in unils (Nilchain's token units).
   *
   * @param blindModule - The module for which the subscription cost is requested (e.g., "nilai" or "nildb").
   * @returns Promise resolving to the numeric subscription cost.
   */
  subscriptionCost(
    blindModule: BlindModule,
  ): Promise<SubscriptionCostResponse> {
    return unwrapEffect(this.subscriptionCostEffect(blindModule));
  }

  /**
   * Effect-based implementation for fetching the current subscription cost.
   *
   * Provides the same functionality as `subscriptionCost()` but returns an
   * Effect that can be composed with other operations.
   *
   * @param blindModule - The module for which the subscription cost is requested (e.g., "nilai" or "nildb").
   * @returns Effect resolving to the subscription cost or failing with typed errors.
   */
  subscriptionCostEffect(
    blindModule: BlindModule,
  ): E.Effect<
    SubscriptionCostResponse,
    ZodError | InvalidContentType | FetchError
  > {
    const url = NilauthUrl.payments.cost(this.nilauthBaseUrl, blindModule);
    const request: RequestOptions = { url, method: "GET" };

    return pipe(
      fetchWithTimeout(request),
      extractResponseJson(),
      parseWithZodSchema(SubscriptionCostResponseSchema),
      assertType<SubscriptionCostResponse>(),
      logOutcome(request),
    );
  }

  /**
   * Check the current subscription status with the Nilauth service.
   *
   * Returns information about whether the client is subscribed and if so,
   * the subscription's expiration and renewal details.
   *
   * @param publicKey - The public key whose subscription status will be checked. This key does not need to belong to the payer.
   * @param blindModule - The module for which the subscription status is checked (e.g., "nilai" or "nildb").
   * @returns Promise resolving to the subscription status.
   */
  subscriptionStatus(
    publicKey: Hex,
    blindModule: BlindModule,
  ): Promise<SubscriptionStatusResponse> {
    return unwrapEffect(this.subscriptionStatusEffect(publicKey, blindModule));
  }

  /**
   * Effect-based implementation for checking subscription status.
   *
   * Returns `{ subscribed: false, details: null }` if not subscribed, or
   * `{ subscribed: true, details: {...} }` with expiration details if subscribed.
   *
   * @param publicKey - The public key whose subscription status will be checked. This key does not need to belong to the payer.
   * @param blindModule - The module for which the subscription status is checked (e.g., "nilai" or "nildb").
   * @returns Effect resolving to the subscription status or failing with typed errors.
   */
  subscriptionStatusEffect(
    publicKey: Hex,
    blindModule: BlindModule,
  ): E.Effect<
    SubscriptionStatusResponse,
    ZodError | InvalidContentType | FetchError
  > {
    const url = NilauthUrl.subscriptions.status(
      this.nilauthBaseUrl,
      publicKey,
      blindModule,
    );
    const request: RequestOptions = {
      url,
      method: "GET",
      headers: { "Content-Type": "application/json" },
    };

    return pipe(
      fetchWithTimeout(request),
      extractResponseJson(),
      parseWithZodSchema(SubscriptionStatusResponseSchema),
      E.catchTag("NilauthErrorResponse", (response) => {
        if (
          response.code === NilauthErrorCodeSchema.enum.NOT_SUBSCRIBED ||
          response.code === NilauthErrorCodeSchema.enum.TRANSACTION_LOOKUP
        ) {
          // Return a "subscribed: false" success value
          const status: SubscriptionStatusResponse = {
            subscribed: false,
            details: null,
          };
          return E.succeed(status);
        }
        // Re-throw the error for other cases
        return E.fail(response);
      }),
      assertType<SubscriptionStatusResponse>(),
      logOutcome(request),
    );
  }

  /**
   * Complete end-to-end payment flow for a Nilauth subscription.
   *
   * This method performs three steps:
   * 1. Fetches the current subscription cost
   * 2. Makes a payment transaction on Nilchain
   * 3. Validates the payment with the Nilauth service
   *
   * @returns Promise resolving when payment and validation succeed, or throws on failure.
   */
  payAndValidate(publicKey: string, blindModule: BlindModule): Promise<void> {
    return unwrapEffect(
      pipe(
        this.subscriptionCostEffect(blindModule),
        E.flatMap((cost) => this.payEffect(cost, blindModule)),
        E.flatMap(({ txHash, payloadHex }) =>
          this.validatePaymentEffect({ publicKey, txHash, payloadHex }),
        ),
      ),
    );
  }

  /**
   * Create and submit a payment transaction for a subscription.
   *
   * Uses the configured payer to submit a transaction to Nilchain for the specified amount.
   *
   * @param amount - The payment amount in unils.
   * @param blindModule - The module for which the payment is made (e.g., "nilai" or "nildb").
   * @returns Effect resolving to the transaction hash and payload, or failing with a payment error.
   */
  payEffect(
    amount: number,
    blindModule: BlindModule,
  ): E.Effect<{ txHash: string; payloadHex: Hex }, PaymentTxFailed> {
    const payload = JSON.stringify({
      nonce: generateNonce(),
      service_public_key: this.nilauthPublicKey,
      blind_module: blindModule,
    });
    const payloadHex = toHex(payload);
    const payloadDigest = sha256(payload);
    log(
      `Making payment with payload=${payloadHex}, digest=${bytesToHex(payloadDigest)}`,
    );

    const request = {
      hash: sha256(payload),
      cost: amount,
    };

    return pipe(
      E.tryPromise({
        try: () => this.payer.pay(request.hash, request.cost),
        catch: (cause) => new PaymentTxFailed({ cause }),
      }),
      E.map((txHash) => ({ txHash, payloadHex })),
    );
  }

  /**
   * Notify the Nilauth service about a completed payment transaction.
   *
   * After making a payment on Nilchain, this method validates the transaction with
   * the Nilauth service to activate the subscription. It automatically retries
   * if the transaction has not yet been committed to the blockchain.
   *
   * @param config - Configuration object containing:
   * - `publicKey`: The public key of the account for which to activate the subscription.
   * - `txHash`: The transaction hash of the payment made on Nilchain.
   * - `payloadHex`: The hex-encoded payload used in the payment transaction.
   * @returns Effect resolving to the validation response or failing with typed errors.
   */
  validatePaymentEffect(config: {
    publicKey: string;
    txHash: string;
    payloadHex: Hex;
  }): E.Effect<
    ValidatePaymentResponse,
    ZodError | InvalidContentType | FetchError
  > {
    const { publicKey, txHash, payloadHex } = config;
    const url = NilauthUrl.payments.validate(this.nilauthBaseUrl);

    const request: RequestOptions = {
      url,
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: {
        tx_hash: txHash,
        payload: payloadHex,
        public_key: publicKey,
      },
    };

    const retry = {
      baseDelay: D.millis(200),
      max: 3,
    };

    const schedule = S.exponential(retry.baseDelay)
      .pipe(S.jittered)
      .pipe((s) => S.intersect(s, S.recurs(retry.max)))
      .pipe((s) =>
        S.onDecision(s, (delay, decision) =>
          E.sync(() => {
            switch (decision._tag) {
              case "Continue":
                log(
                  `Retrying request to ${request.url} after ${delay}ms delay`,
                );
                break;
              case "Done":
                log(`Retries exhausted for ${request.url}`);
                break;
              default:
                break;
            }
          }),
        ),
      );

    return pipe(
      fetchWithTimeout(request),
      E.retry({
        schedule,
        while: (error) =>
          error instanceof NilauthErrorResponse &&
          error.code === NilauthErrorCodeSchema.enum.TRANSACTION_NOT_COMMITTED,
      }),
      extractResponseJson(),
      parseWithZodSchema(ValidatePaymentResponseSchema),
      assertType<ValidatePaymentResponse>(),
      logOutcome(request),
    );
  }

  /**
   * Request a new NUC token from the Nilauth service.
   *
   * Creates a fresh token that can be used for authentication and authorization
   * with Nilauth and compatible services.
   *
   * Requesting tokens can only be done if a subscription for the blind module is paid.
   *
   * @param keypair - The keypair used to sign the request.
   * @param blindModule - The module for which the token is requested (e.g., "nilai" or "nildb").
   * @returns Promise resolving to the created token response.
   */
  requestToken(
    keypair: Keypair,
    blindModule: BlindModule,
  ): Promise<CreateTokenResponse> {
    return pipe(this.requestTokenEffect(keypair, blindModule), unwrapEffect);
  }

  /**
   * Effect-based implementation for requesting a new NUC token.
   *
   * Provides the same functionality as `requestToken()` but returns an
   * Effect that can be composed with other operations.
   *
   * @param keypair - The keypair used to sign the request.
   * @param blindModule - The module for which the token is requested (e.g., "nilai" or "nildb").
   * @returns Effect resolving to the created token response or failing with typed errors.
   */
  requestTokenEffect(
    keypair: Keypair,
    blindModule: BlindModule,
  ): E.Effect<CreateTokenResponse, ZodError | InvalidContentType | FetchError> {
    const url = NilauthUrl.nucs.create(this.nilauthBaseUrl);
    const body = createSignedRequest(
      {
        nonce: generateNonce(),
        target_public_key: this.nilauthPublicKey,
        expires_at: Math.floor(
          Temporal.Now.instant().add({ seconds: 60 }).epochMilliseconds / 1000,
        ),
        blind_module: blindModule,
      },
      keypair,
    );
    const request: RequestOptions = {
      url,
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body,
    };

    return pipe(
      fetchWithTimeout(request),
      extractResponseJson(),
      parseWithZodSchema(CreateTokenResponseSchema),
      assertType<CreateTokenResponse>(),
      logOutcome(request),
    );
  }

  /**
   * Revoke a previously issued NUC token.
   *
   * This invalidates the specified token by registering a revocation with the
   * Nilauth service. Any future verification of this token should fail.
   *
   * @param config - Configuration object containing:
   * - `keypair`: The keypair used to sign the revocation request.
   * - `authToken`: The NUC token envelope used for authentication.
   * - `tokenToRevoke`: The NUC token envelope to be revoked.
   * @returns Promise resolving when revocation is successfully registered.
   */
  revokeToken(config: {
    keypair: Keypair;
    authToken: NucTokenEnvelope;
    tokenToRevoke: NucTokenEnvelope;
  }): Promise<void> {
    const { keypair, authToken, tokenToRevoke } = config;
    const revokeTokenInvocation = NucTokenBuilder.extending(authToken)
      .body(new InvocationBody({ token: tokenToRevoke.serialize() }))
      .command(REVOKE_COMMAND)
      .audience(Did.fromHex(this.nilauthPublicKey))
      .build(keypair.privateKey());
    return unwrapEffect(this.revokeTokenEffect(revokeTokenInvocation));
  }

  /**
   * Effect-based implementation for submitting a token revocation.
   *
   * Sends a revocation invocation to the Nilauth service to invalidate
   * the specified token.
   *
   * @param revokeTokenInvocation - The serialized revocation invocation.
   * @returns Effect resolving when revocation succeeds or failing with typed errors.
   */
  revokeTokenEffect(
    revokeTokenInvocation: string,
  ): E.Effect<void, ZodError | InvalidContentType | FetchError> {
    const url = NilauthUrl.nucs.revoke(this.nilauthBaseUrl);
    const request: RequestOptions = {
      url,
      method: "POST",
      headers: { Authorization: `Bearer ${revokeTokenInvocation}` },
    };

    return pipe(
      fetchWithTimeout(request),
      extractResponseJson(),
      parseWithZodSchema(ValidatePaymentResponseSchema),
      assertType<ValidatePaymentResponse>(),
      logOutcome({ url, method: "POST" }),
    );
  }

  /**
   * Asks the nilauth server to provide, if any, revoked tokens in the proof chain. If any revocations are returned
   * then any entity receiving the provided token should reject it.
   *
   * @param token - The envelope of the token to check.
   * @returns Promise resolving to the lookup response.
   */
  findRevocationsInProofChain(
    token: NucTokenEnvelope,
  ): Promise<LookupRevokedTokenResponse> {
    return unwrapEffect(
      NilauthClient.findRevocationsInProofChainEffect(
        this.nilauthBaseUrl,
        token,
      ),
    );
  }
}

/**
 * Pipeable combinator to log the outcome (success or failure) of an Effect.
 *
 * Attaches debug logging to any Effect, recording when a request succeeds or fails.
 * Uses the debug log facility with the "@nillion/nuc" namespace.
 *
 * @param request - The request options containing the URL and HTTP method.
 * @returns A function that enhances the Effect with logging of outcomes.
 */
function logOutcome<A, E>(
  request: RequestOptions,
): (effect: E.Effect<A, E>) => E.Effect<A, E> {
  const { method, url } = request;

  return (effect) =>
    effect.pipe(
      E.tapBoth({
        onFailure: (e) =>
          E.sync(() =>
            log(`Request failed: method=${method} url=${url} error=${e}`),
          ),
        onSuccess: () =>
          E.sync(() => log(`Request succeeded: method=${method} url=${url}`)),
      }),
    );
}
