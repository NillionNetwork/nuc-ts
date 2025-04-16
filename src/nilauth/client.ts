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
 * token issuance, revocation, and proof chain lookups.
 * Uses effectful, composable pipelines for all network operations.
 */
export class NilauthClient {
  #options: NilauthClientOptions;

  /**
   * Construct a NilauthClient from options.
   * @param options - Client configuration including keypair, payer, and nilauth service info.
   * @returns A new NilauthClient instance.
   */
  constructor(options: NilauthClientOptions) {
    this.#options = options;
  }

  /**
   * Initialise a NilauthClient by fetching the service's public key.
   * @param options - Object with `baseUrl`, `keypair`, and `payer`.
   * @returns Promise resolving to a ready-to-use NilauthClient.
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
   * Fetch service metadata for a given Nilauth base URL.
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
   * Perform a health check for a given Nilauth base URL.
   * @param serviceUrl - The base URL of the Nilauth service.
   * @returns Promise resolving to the service health response.
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

  /** The nilchain payer used for subscription payments. */
  get payer(): Payer {
    return this.#options.payer;
  }

  /** The client's keypair. */
  get keypair(): Keypair {
    return this.#options.keypair;
  }

  /** The Nilauth service's public key. */
  get nilauthPublicKey(): string {
    return this.#options.nilauth.publicKey;
  }

  /** The Nilauth service's base URL. */
  get nilauthBaseUrl(): string {
    return this.#options.nilauth.baseUrl;
  }

  /**
   * Get nilauth service information for the configured base URL.
   * @returns Promise resolving to the service metadata.
   */
  about(): Promise<NilauthAboutResponse> {
    return NilauthClient.about(this.nilauthBaseUrl);
  }

  /**
   * Perform a health check against the nilauth service.
   * @returns Promise resolving to the service health response.
   */
  health(): Promise<NilauthHealthResponse> {
    return NilauthClient.health(this.nilauthBaseUrl);
  }

  /**
   * Fetch the current subscription cost.
   */
  subscriptionCost(): Promise<SubscriptionCostResponse> {
    return unwrapEffect(this.subscriptionCostEffect());
  }

  /**
   * Fetch the current subscription cost.
   * @returns Promise resolving to the subscription cost.
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
   * Fetch the current subscription status.
   * @returns Promise resolving to the subscription status.
   */
  subscriptionStatus(): Promise<SubscriptionStatusResponse> {
    return unwrapEffect(this.subscriptionStatusEffect());
  }

  /**
   * Effectful fetch of the current subscription status.
   * Returns `{ subscribed: false, details: null }` if not subscribed.
   * @returns Effect resolving to the subscription status or failing with a typed error.
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
   * Pay for a subscription on nilchain and then validate the payment with nilauth.
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
   * Initiate a payment for a subscription.
   * @param amount - The payment amount.
   * @returns Effect resolving to the transaction hash and payload used, or failing with a payment error.
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
   * Validate a payment transaction by hash and payload.
   * Retries if the transaction is not yet committed.
   * @param txHash - The transaction hash.
   * @param payloadHex - The hex-encoded payment payload.
   * @returns Effect resolving to the validation response or failing with a typed error.
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
   * Request a new token from Nilauth.
   * @returns Promise resolving to the created token response.
   */
  requestToken(): Promise<CreateTokenResponse> {
    return pipe(this.requestTokenEffect(), unwrapEffect);
  }

  /**
   * Effectful request for a new token from Nilauth.
   * @returns Effect resolving to the created token response or failing with a typed error.
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
   * Revoke a token by submitting a revocation invocation.
   * @param tokenToRevoke - The envelope of the token to revoke.
   * @returns Promise resolving when revocation is complete.
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
   * Revoke a token by submitting a revocation invocation.
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
   * Lookup revoked tokens in the proof chain.
   * @param token - The envelope of the token to check.
   * @returns Promise resolving to the lookup response.
   */
  lookupRevokedTokens(
    token: NucTokenEnvelope,
  ): Promise<LookupRevokedTokenResponse> {
    return unwrapEffect(this.findRevocationsInProofChainEffect(token));
  }

  /**
   * Effectful lookup of revoked tokens in the proof chain.
   * @param token - The envelope of the token to check.
   * @returns Effect resolving to the lookup response or failing with a typed error.
   */
  findRevocationsInProofChainEffect(
    token: NucTokenEnvelope,
  ): E.Effect<
    LookupRevokedTokenResponse,
    ZodError | InvalidContentType | FetchError
  > {
    const url = NilauthUrl.nucs.findRevocations(this.nilauthBaseUrl);
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
}

/**
 * Pipeable combinator to log the outcome (success or failure) of an Effect.
 *
 * @param request - The request options, including URL and method.
 * @returns A function that logs the outcome of the effect.
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
