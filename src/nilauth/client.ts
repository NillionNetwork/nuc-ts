import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex } from "@noble/hashes/utils";
import { Duration as D, Effect as E, Schedule as S, pipe } from "effect";
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
  type RequestOptions,
  fetchWithTimeout,
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
  type Hex,
  assertType,
  createSignedRequest,
  extractResponseJson,
  extractResponseText,
  generateNonce,
  parseWithZodSchema,
  toHex,
  unwrapEffect,
} from "#/utils";

/**
 * Options required to construct a NilauthClient.
 */
export type NilauthClientOptions = {
  keypair: Keypair;
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
   * @param options - Configuration object containing `baseUrl`, `keypair`, and `payer`.
   * @returns Promise resolving to a fully configured NilauthClient instance.
   */
  static async from(options: {
    baseUrl: string;
    keypair: Keypair;
    payer: Payer;
  }): Promise<NilauthClient> {
    const { baseUrl, keypair, payer } = options;

    const about = await NilauthClient.about(baseUrl);

    return new NilauthClient({
      keypair,
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
   * The client's keypair used for signing requests.
   * Contains both the public and private keys.
   */
  get keypair(): Keypair {
    return this.#options.keypair;
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
   * @returns Promise resolving to the numeric subscription cost.
   */
  subscriptionCost(): Promise<SubscriptionCostResponse> {
    return unwrapEffect(this.subscriptionCostEffect());
  }

  /**
   * Effect-based implementation for fetching the current subscription cost.
   *
   * Provides the same functionality as `subscriptionCost()` but returns an
   * Effect that can be composed with other operations.
   *
   * @returns Effect resolving to the subscription cost or failing with typed errors.
   */
  subscriptionCostEffect(): E.Effect<
    SubscriptionCostResponse,
    ZodError | InvalidContentType | FetchError
  > {
    const url = NilauthUrl.payments.cost(this.nilauthBaseUrl);
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
   * @returns Promise resolving to the subscription status.
   */
  subscriptionStatus(): Promise<SubscriptionStatusResponse> {
    return unwrapEffect(this.subscriptionStatusEffect());
  }

  /**
   * Effect-based implementation for checking subscription status.
   *
   * Returns `{ subscribed: false, details: null }` if not subscribed, or
   * `{ subscribed: true, details: {...} }` with expiration details if subscribed.
   *
   * @returns Effect resolving to the subscription status or failing with typed errors.
   */
  subscriptionStatusEffect(): E.Effect<
    SubscriptionStatusResponse,
    ZodError | InvalidContentType | FetchError
  > {
    const url = NilauthUrl.subscriptions.status(this.nilauthBaseUrl);
    const body = createSignedRequest(
      {
        nonce: generateNonce(),
        expires_at: Temporal.Now.instant().add({ seconds: 60 }).epochSeconds,
      },
      this.keypair,
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
      parseWithZodSchema(SubscriptionStatusResponseSchema),
      E.catchTag("NilauthErrorResponse", (response) => {
        if (response.code === NilauthErrorCodeSchema.enum.NOT_SUBSCRIBED) {
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
  payAndValidate(): Promise<void> {
    return unwrapEffect(
      pipe(
        this.subscriptionCostEffect(),
        E.flatMap((cost) => this.payEffect(cost)),
        E.flatMap(({ txHash, payloadHex }) =>
          this.validatePaymentEffect(txHash, payloadHex),
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
   * @returns Effect resolving to the transaction hash and payload, or failing with a payment error.
   */
  payEffect(
    amount: number,
  ): E.Effect<{ txHash: string; payloadHex: Hex }, PaymentTxFailed> {
    const payload = JSON.stringify({
      nonce: generateNonce(),
      service_public_key: this.nilauthPublicKey,
    });
    const payloadHex = toHex(payload);

    const request = {
      payload: payloadHex,
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
   * @param txHash - The transaction hash from the Nilchain payment.
   * @param payloadHex - The hex-encoded payment payload used in the transaction.
   * @returns Effect resolving to the validation response or failing with typed errors.
   */
  validatePaymentEffect(
    txHash: string,
    payloadHex: Hex,
  ): E.Effect<
    ValidatePaymentResponse,
    ZodError | InvalidContentType | FetchError
  > {
    const url = NilauthUrl.payments.validate(this.nilauthBaseUrl);

    const request: RequestOptions = {
      url,
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: {
        tx_hash: txHash,
        payload: payloadHex,
        public_key: this.keypair.publicKey("hex"),
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
   * @returns Promise resolving to the created token response.
   */
  requestToken(): Promise<CreateTokenResponse> {
    return pipe(this.requestTokenEffect(), unwrapEffect);
  }

  /**
   * Effect-based implementation for requesting a new NUC token.
   *
   * Provides the same functionality as `requestToken()` but returns an
   * Effect that can be composed with other operations.
   *
   * @returns Effect resolving to the created token response or failing with typed errors.
   */
  requestTokenEffect(): E.Effect<
    CreateTokenResponse,
    ZodError | InvalidContentType | FetchError
  > {
    const url = NilauthUrl.nucs.create(this.nilauthBaseUrl);
    const body = createSignedRequest(
      {
        nonce: generateNonce(),
        target_public_key: this.nilauthPublicKey,
        expires_at: Temporal.Now.instant().add({ seconds: 60 }).epochSeconds,
      },
      this.keypair,
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
   * @param tokenToRevoke - The token envelope to revoke.
   * @returns Promise resolving when revocation is successfully registered.
   */
  revokeToken(tokenToRevoke: NucTokenEnvelope): Promise<void> {
    return unwrapEffect(
      pipe(
        this.requestTokenEffect(),
        E.map((envelope) => {
          return NucTokenBuilder.extending(envelope.token)
            .body(new InvocationBody({ token: tokenToRevoke.serialize() }))
            .command(REVOKE_COMMAND)
            .audience(Did.fromHex(this.nilauthPublicKey))
            .build(this.keypair.privateKey());
        }),
        E.flatMap((revokeTokenInvocation) =>
          this.revokeTokenEffect(revokeTokenInvocation),
        ),
      ),
    );
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
