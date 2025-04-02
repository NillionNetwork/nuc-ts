import { randomBytes } from "node:crypto";
import { secp256k1 } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex } from "@noble/hashes/utils";
import { Effect as E, pipe } from "effect";
import { Temporal } from "temporal-polyfill";
import z from "zod";
import { NucTokenBuilder } from "#/builder";
import { type NucTokenEnvelope, NucTokenEnvelopeSchema } from "#/envelope";
import type { Keypair } from "#/keypair";
import { log } from "#/logger";
import type { Payer } from "#/payer/client";
import type { TxHash } from "#/payer/types";
import { Did, InvocationBody, REVOKE_COMMAND } from "#/token";

const PAYMENT_TX_RETRIES = [1000, 2000, 3000, 5000, 10000, 10000, 10000];
const TX_RETRY_ERROR_CODE = "TRANSACTION_NOT_COMMITTED";

export const NilauthHealthResponseSchema = z.literal("OK");
export type NilauthHealthResponse = z.infer<typeof NilauthHealthResponseSchema>;

export const BuildSchema = z
  .object({
    commit: z.string(),
    timestamp: z.string(),
  })
  .transform(({ commit, timestamp }) => ({
    commit,
    timestamp: Temporal.Instant.from(timestamp),
  }));

export const NilauthAboutResponseSchema = z
  .object({
    started: z.string(),
    public_key: z.string(),
    build: BuildSchema,
  })
  .transform(({ started, public_key, build }) => ({
    started: Temporal.Instant.from(started),
    publicKey: public_key,
    build,
  }));
export type NilauthAboutResponse = z.infer<typeof NilauthAboutResponseSchema>;

export const SubscriptionCostResponseSchema = z
  .object({
    cost_unils: z.number(),
  })
  .transform(({ cost_unils }) => cost_unils);
export type SubscriptionCostResponse = z.infer<
  typeof SubscriptionCostResponseSchema
>;

export const CreateTokenResponseSchema = z.object({
  token: NucTokenEnvelopeSchema,
});
export type CreateTokenResponse = z.infer<typeof CreateTokenResponseSchema>;

export const RevokedTokenSchema = z
  .object({
    token_hash: z.string(),
    revoked_at: z.string(),
  })
  .transform(({ token_hash, revoked_at }) => ({
    tokenHash: token_hash,
    revokedAt: revoked_at,
  }));
export type RevokedToken = z.infer<typeof RevokedTokenSchema>;

export const LookupRevokedTokenResponseSchema = z.object({
  revoked: z.array(RevokedTokenSchema),
});
export type LookupRevokedTokenResponse = z.infer<
  typeof LookupRevokedTokenResponseSchema
>;

type ValidatePaymentRequest = {
  tx_hash: TxHash;
  payload: string;
  public_key: string;
};

export class NilauthClient {
  constructor(
    private baseUrl: string,
    private timeout = 10000,
  ) {}

  async health(): Promise<NilauthHealthResponse> {
    return pipe(
      E.tryPromise(() =>
        sendRequest({ url: `${this.baseUrl}/health`, timeout: this.timeout }),
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
      sleepTimes: PAYMENT_TX_RETRIES,
      retryCondition: (error) => error.code === TX_RETRY_ERROR_CODE,
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

const NilauthErrorSchema = z
  .object({
    error_code: z.string(),
    message: z.string(),
  })
  .transform(({ error_code, message }) => ({
    code: error_code,
    message,
  }));
type NilauthError = z.infer<typeof NilauthErrorSchema>;

type Request = {
  url: string;
  timeout: number;
  init?: RequestInit;
  sleepTimes?: number[];
  retryCondition?: (error: NilauthError) => boolean;
};
async function sendRequest(request: Request): Promise<unknown> {
  const {
    url,
    timeout,
    init,
    sleepTimes = [0],
    retryCondition = (_) => false,
  } = request;
  for (const sleepTime of sleepTimes) {
    const response = await fetchWithTimeout(url, timeout, init);
    const contentType = response.headers.get("content-type");
    if (!contentType) {
      throw E.fail("content-type not found");
    }
    if (contentType?.includes("text/plain")) {
      return await response.text();
    }
    if (contentType !== "application/json") {
      throw E.fail("unsupported content-type");
    }
    const body = await response.json();
    if (!response.ok) {
      const error = NilauthErrorSchema.parse(body);
      if (!retryCondition(error)) {
        throw new Error(`${error.code}: ${error.message}`);
      }
      log(`retrying in ${sleepTime}`);
      await new Promise((f) => setTimeout(f, sleepTime));
    } else {
      return body;
    }
  }
  throw E.fail("request failed: max retries");
}

async function fetchWithTimeout(
  url: string,
  timeout: number,
  init?: RequestInit,
): Promise<Response> {
  const timeoutPromise = new Promise((_, reject) =>
    setTimeout(() => reject("timeout"), timeout),
  );
  return (await Promise.race([fetch(url, init), timeoutPromise])) as Response;
}
