/**
 * Nilauth client
 */

import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex } from "@noble/hashes/utils";
import { Effect as E, pipe } from "effect";
import { Temporal } from "temporal-polyfill";
import { NucTokenBuilder } from "#/builder";
import type { NucTokenEnvelope } from "#/envelope";
import type { Keypair } from "#/keypair";
import { log } from "#/logger";
import { type NilauthError, sendRequest } from "#/nilauth/request-sender";
import {
  type CreateTokenResponse,
  CreateTokenResponseSchema,
  type LookupRevokedTokenResponse,
  LookupRevokedTokenResponseSchema,
  type NilauthAboutResponse,
  NilauthAboutResponseSchema,
  type NilauthHealthResponse,
  NilauthHealthResponseSchema,
  type SignedRequest,
  type SubscriptionCostResponse,
  SubscriptionCostResponseSchema,
  type SubscriptionStatusResponse,
  SubscriptionStatusResponseSchema,
  type ValidatePaymentRequest,
  type ValidatePaymentResponse,
  ValidatePaymentResponseSchema,
} from "#/nilauth/types";
import type { Payer } from "#/payer/client";
import { Did, InvocationBody, REVOKE_COMMAND } from "#/token";
import { randomBytes } from "#/utils";
import { type Hex, toHex } from "#/utils";

const PAYMENT_TX_RETRIES = [1000, 2000, 3000, 5000, 10000, 10000, 10000];
const TX_RETRY_ERROR_CODE = "TRANSACTION_NOT_COMMITTED";

/**
 * Client to interact with nilauth.
 */
export class NilauthClient {
  /**
   * Creates a NilauthClient instance to interact to nilauth at given url
   * @param baseUrl nilauth's URL
   * @param timeout The default timeout to use for all requests
   */
  constructor(
    private baseUrl: string,
    private timeout = 10000,
  ) {}

  /**
   * Generate a random nonce
   */
  static genNonce(): Hex {
    const bytes = randomBytes(16);
    return Array.from(bytes)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }

  /**
   * Creates a signed request from a given payload
   * @param requestPayload Payload of the request
   * @param keypair Keypair that will be used to create the request. The private key is only used to sign the payload
   * to prove ownership and is never transmitted anywhere.
   */
  private static createSignedRequest(
    requestPayload: unknown,
    keypair: Keypair,
  ): SignedRequest {
    const payload = JSON.stringify(requestPayload);
    return {
      public_key: keypair.publicKey("hex"),
      signature: keypair.sign(payload, "hex"),
      payload: toHex(payload),
    };
  }

  /**
   * Check the health of the nilauth server.
   */
  async health(): Promise<NilauthHealthResponse> {
    return pipe(
      E.tryPromise(() =>
        sendRequest({
          url: `${this.baseUrl}/health`,
          timeout: this.timeout,
        }),
      ),
      E.flatMap((data) => E.try(() => NilauthHealthResponseSchema.parse(data))),
      E.tapBoth({
        onFailure: (e) => E.sync(() => log(`get health failed: ${e.cause}`)),
        onSuccess: (_) => E.sync(() => log("get health successfully")),
      }),
      E.runPromise,
    );
  }

  /**
   * Get information about the nilauth server.
   */
  async about(): Promise<NilauthAboutResponse> {
    return pipe(
      E.tryPromise(() =>
        sendRequest({ url: `${this.baseUrl}/about`, timeout: this.timeout }),
      ),
      E.flatMap((data) => E.try(() => NilauthAboutResponseSchema.parse(data))),
      E.tapBoth({
        onFailure: (e) => E.sync(() => log(`get about failed: ${e.cause}`)),
        onSuccess: (_) => E.sync(() => log("get about successfully")),
      }),
      E.runPromise,
    );
  }

  /**
   * Get the subscription cost in unils.
   */
  async subscriptionCost(): Promise<SubscriptionCostResponse> {
    return pipe(
      E.tryPromise(() =>
        sendRequest({
          url: `${this.baseUrl}/api/v1/payments/cost`,
          timeout: this.timeout,
        }),
      ),
      E.flatMap((data) =>
        E.try(() => SubscriptionCostResponseSchema.parse(data)),
      ),
      E.tapBoth({
        onFailure: (e) =>
          E.sync(() => log(`get subscription cost failed: ${e.cause}`)),
        onSuccess: (_) =>
          E.sync(() => log("get subscription cost successfully")),
      }),
      E.runPromise,
    );
  }

  /**
   * Get the status of the subscription
   * @param keypair The key for which to get the subscription information. The private key is only used to sign the
   * payload to prove ownership and is never transmitted anywhere.
   */
  async subscriptionStatus(
    keypair: Keypair,
  ): Promise<SubscriptionStatusResponse> {
    const request = NilauthClient.createSignedRequest(
      {
        nonce: NilauthClient.genNonce(),
        expires_at: Temporal.Now.instant().add({ seconds: 60 }).epochSeconds,
      },
      keypair,
    );
    return pipe(
      E.tryPromise(() =>
        sendRequest({
          url: `${this.baseUrl}/api/v1/subscriptions/status`,
          timeout: this.timeout,
          init: {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(request),
          },
        }),
      ),
      E.flatMap((response) =>
        E.try(() => SubscriptionStatusResponseSchema.parse(response)),
      ),
      E.tapBoth({
        onFailure: (e) =>
          E.sync(() => log(`request subscription status failed: ${e.cause}`)),
        onSuccess: (_) =>
          E.sync(() => log("request subscription status successfully")),
      }),
      E.runPromise,
    );
  }

  /**
   * Request a token, issued to the public key tied to the given private key.
   * @param keypair The key for which the token should be issued to. The private key is only used to sign the
   * payload to prove ownership and is never transmitted anywhere.
   */
  async requestToken(keypair: Keypair): Promise<CreateTokenResponse> {
    const createRequest = (aboutResponse: NilauthAboutResponse) =>
      NilauthClient.createSignedRequest(
        {
          nonce: NilauthClient.genNonce(),
          target_public_key: aboutResponse.publicKey,
          expires_at: Temporal.Now.instant().add({ seconds: 60 }).epochSeconds,
        },
        keypair,
      );
    return pipe(
      E.tryPromise(() => this.about()),
      E.map(createRequest),
      E.andThen((request) =>
        sendRequest({
          url: `${this.baseUrl}/api/v1/nucs/create`,
          timeout: this.timeout,
          init: {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(request),
          },
        }),
      ),
      E.flatMap((response) =>
        E.try(() => CreateTokenResponseSchema.parse(response)),
      ),
      E.tapBoth({
        onFailure: (e) => E.sync(() => log(`request token failed: ${e.cause}`)),
        onSuccess: (_) => E.sync(() => log("request token successfully")),
      }),
      E.runPromise,
    );
  }

  /**
   * Validates that a payment was made on nilchain
   * @param request The request with the pàyment's information to validate
   * @private
   */
  private async validatePayment(
    request: ValidatePaymentRequest,
  ): Promise<ValidatePaymentResponse> {
    return pipe(
      E.tryPromise(() =>
        sendRequest({
          url: `${this.baseUrl}/api/v1/payments/validate`,
          timeout: this.timeout,
          retryDelays: PAYMENT_TX_RETRIES,
          retryWhile: (error: NilauthError) =>
            error.code === TX_RETRY_ERROR_CODE,
          init: {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(request),
          },
        }),
      ),
      E.flatMap((response) =>
        E.try(() => ValidatePaymentResponseSchema.parse(response)),
      ),
      E.tapBoth({
        onFailure: (e) =>
          E.sync(() => log(`validate payment failed: ${e.cause}`)),
        onSuccess: (_) => E.sync(() => log("validate payment successfully")),
      }),
      E.runPromise,
    );
  }

  /**
   * Pay for a subscription.
   * @param keypair The key the subscription is for. The private key will be used to sign the subscription message
   * request to prove ownership and is never transmitted anywhere.
   * @param payer The payer that will be used.
   */
  async paySubscription(
    keypair: Keypair,
    payer: Payer,
  ): Promise<ValidatePaymentResponse> {
    const buildPayload = (aboutInfo: NilauthAboutResponse, cost: number) => {
      const payload = JSON.stringify({
        nonce: NilauthClient.genNonce(),
        service_public_key: aboutInfo.publicKey,
      });
      return {
        payload: toHex(payload),
        hash: sha256(payload),
        cost,
      };
    };

    return pipe(
      E.tryPromise(() => this.subscriptionStatus(keypair)),
      E.andThen((subscriptionStatus) => {
        const now = Temporal.Now.instant();
        if (
          subscriptionStatus.subscribed &&
          subscriptionStatus.details &&
          subscriptionStatus.details.renewableAt.epochSeconds > now.epochSeconds
        ) {
          return E.fail(
            new Error("subscription cannot be renewed", {
              cause: `cannot renew before ${subscriptionStatus.details.renewableAt}`,
            }),
          );
        }
        return pipe(
          E.all([
            E.tryPromise(() => this.about()),
            E.tryPromise(() => this.subscriptionCost()),
          ]),
          E.map(([aboutInfo, cost]) => buildPayload(aboutInfo, cost)),
          E.flatMap(({ payload, hash, cost }) =>
            pipe(
              E.tryPromise(() => payer.pay(hash, cost)),
              E.map((txHash) => ({ payload, txHash })),
            ),
          ),
          E.andThen(({ payload, txHash }) =>
            this.validatePayment({
              tx_hash: txHash,
              payload,
              public_key: keypair.publicKey("hex"),
            }),
          ),
        );
      }),
      E.tapBoth({
        onFailure: (e) =>
          E.sync(() => log(`subscription pay failed: ${e.cause}`)),
        onSuccess: (_) =>
          E.sync(() => log("subscription has been paid successfully")),
      }),
      E.runPromise,
    );
  }

  /**
   * Revoke a token.
   * @param keypair The key to use to mint the token.
   * @param token The token to be revoked.
   */
  async revokeToken(keypair: Keypair, token: NucTokenEnvelope): Promise<void> {
    return pipe(
      E.all([
        E.tryPromise(() => this.about()),
        E.tryPromise(() => this.requestToken(keypair)),
      ]),
      E.flatMap(([aboutInfo, authToken]) =>
        E.try(() => {
          authToken.token.validateSignatures();
          return NucTokenBuilder.extending(authToken.token)
            .body(new InvocationBody({ token: token.serialize() }))
            .command(REVOKE_COMMAND)
            .audience(Did.fromHex(aboutInfo.publicKey))
            .build(keypair.privateKey());
        }),
      ),
      E.andThen((invocation) => {
        sendRequest({
          url: `${this.baseUrl}/api/v1/revocations/revoke`,
          timeout: this.timeout,
          init: {
            method: "POST",
            headers: { Authorization: `Bearer ${invocation}` },
          },
        });
      }),
      E.tapBoth({
        onFailure: (e) =>
          E.sync(() => log(`token revocation failed: ${e.cause}`)),
        onSuccess: (_) => E.sync(() => log("token was revoked successfully")),
      }),
      E.runPromise,
    );
  }

  /**
   * Lookup revoked token that would invalidate the given token
   * @param token The token to do lookups for.
   */
  async lookupRevokedTokens(
    token: NucTokenEnvelope,
  ): Promise<LookupRevokedTokenResponse> {
    const request = {
      hashes: [token.token, ...token.proofs].map((token) =>
        bytesToHex(token.computeHash()),
      ),
    };
    return pipe(
      E.tryPromise(() =>
        sendRequest({
          url: `${this.baseUrl}/api/v1/revocations/lookup`,
          timeout: this.timeout,
          init: {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(request),
          },
        }),
      ),
      E.flatMap((data) =>
        E.try(() => LookupRevokedTokenResponseSchema.parse(data)),
      ),
      E.tapBoth({
        onFailure: (e) =>
          E.sync(() => log(`lookup revoked tokens failed: ${e.cause}`)),
        onSuccess: (_) =>
          E.sync(() => log("lookup revoked tokens finished successfully")),
      }),
      E.runPromise,
    );
  }
}
