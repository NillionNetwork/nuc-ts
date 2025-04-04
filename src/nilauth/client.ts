import { randomBytes } from "node:crypto";
import { secp256k1 } from "@noble/curves/secp256k1";
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
  type SubscriptionCostResponse,
  SubscriptionCostResponseSchema,
  type ValidatePaymentRequest,
} from "#/nilauth/types";
import type { Payer } from "#/payer/client";
import { Did, InvocationBody, REVOKE_COMMAND } from "#/token";

const PAYMENT_TX_RETRIES = [1000, 2000, 3000, 5000, 10000, 10000, 10000];
const TX_RETRY_ERROR_CODE = "TRANSACTION_NOT_COMMITTED";

export class NilauthClient {
  constructor(
    private baseUrl: string,
    private timeout = 10000,
  ) {}

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

  async requestToken(keypair: Keypair): Promise<CreateTokenResponse> {
    const aboutResponse = await this.about();

    const payload = JSON.stringify({
      nonce: randomBytes(16).toString("hex"),
      target_public_key: aboutResponse.publicKey,
      expires_at: Temporal.Now.instant().add({ seconds: 60 }).epochSeconds,
    });

    const signature = secp256k1.sign(
      new Uint8Array(Buffer.from(payload)),
      keypair.privateKey(),
      { prehash: true },
    );
    const request = {
      public_key: keypair.publicKey("hex"),
      signature: signature.toCompactHex(),
      payload: Buffer.from(payload).toString("hex"),
    };
    return pipe(
      E.tryPromise(() =>
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

  async validatePayment(request: ValidatePaymentRequest): Promise<void> {
    await sendRequest({
      url: `${this.baseUrl}/api/v1/payments/validate`,
      timeout: this.timeout,
      retryDelays: PAYMENT_TX_RETRIES,
      retryWhile: (error: NilauthError) => error.code === TX_RETRY_ERROR_CODE,
      init: {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(request),
      },
    });
  }

  async paySubscription(publicKey: string, payer: Payer): Promise<void> {
    const buildPayload = (aboutInfo: NilauthAboutResponse, cost: number) => {
      const payload = JSON.stringify({
        nonce: randomBytes(16).toString("hex"),
        service_public_key: aboutInfo.publicKey,
      });
      return {
        payload: Buffer.from(payload).toString("hex"),
        hash: sha256(payload),
        cost,
      };
    };

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
      E.andThen(({ payload, txHash }) => ({
        tx_hash: txHash,
        payload,
        public_key: publicKey,
      })),
      E.andThen((request) => this.validatePayment(request)),
      E.tapBoth({
        onFailure: (e) =>
          E.sync(() => log(`subscription pay failed: ${e.cause}`)),
        onSuccess: (_) =>
          E.sync(() => log("subscription has been paid successfully")),
      }),
      E.runPromise,
    );
  }

  async revokeToken(
    keypair: Keypair,
    envelope: NucTokenEnvelope,
  ): Promise<void> {
    return pipe(
      E.all([
        E.tryPromise(() => this.about()),
        E.tryPromise(() => this.requestToken(keypair)),
      ]),
      E.flatMap(([aboutInfo, authToken]) =>
        E.try(() => {
          authToken.token.validateSignatures();
          return NucTokenBuilder.extending(authToken.token)
            .body(new InvocationBody({ token: envelope.serialize() }))
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

  async lookupRevokedTokens(
    envelope: NucTokenEnvelope,
  ): Promise<LookupRevokedTokenResponse> {
    const request = {
      hashes: [envelope.token, ...envelope.proofs].map((token) =>
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
