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

export class NilauthClient {
  constructor(
    private baseUrl: string,
    private timeout = 10000,
  ) {}

  async about(): Promise<NilauthAboutResponse> {
    return pipe(
      E.tryPromise(() =>
        fetchWithTimeout(`${this.baseUrl}/about`, this.timeout),
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
        fetchWithTimeout(`${this.baseUrl}/api/v1/payments/cost`, this.timeout),
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
        fetchWithTimeout(`${this.baseUrl}/api/v1/nucs/create`, this.timeout, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(request),
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

    type ValidatePaymentRequest = {
      tx_hash: TxHash;
      payload: string;
      public_key: string;
    };
    const validatePayment = (request: ValidatePaymentRequest) => {
      fetchWithTimeout(
        `${this.baseUrl}/api/v1/payments/validate`,
        this.timeout,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(request),
        },
      );
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
      E.andThen(validatePayment),
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
        fetchWithTimeout(
          `${this.baseUrl}/api/v1/revocations/revoke`,
          this.timeout,
          {
            method: "POST",
            headers: { Authorization: `Bearer ${invocation}` },
          },
        );
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
        fetchWithTimeout(
          `${this.baseUrl}/api/v1/revocations/lookup`,
          this.timeout,
          {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(request),
          },
        ),
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

async function fetchWithTimeout(
  url: string,
  timeout: number,
  init?: RequestInit,
): Promise<unknown> {
  const fetchPromise = pipe(
    E.tryPromise(() => fetch(url, init)),
    E.andThen(getResponseBody),
    E.andThen(raiseForStatus),
    E.runPromise,
  );

  const timeoutPromise = new Promise((_, reject) =>
    setTimeout(() => reject("timeout"), timeout),
  );

  return Promise.race([fetchPromise, timeoutPromise]);
}

type ResponseBody = {
  response: Response;
  body: Record<string, unknown>;
};

async function getResponseBody(response: Response): Promise<ResponseBody> {
  return {
    response,
    body: (await response.json()) as Record<string, unknown>,
  };
}

function raiseForStatus(responseBody: ResponseBody): E.Effect<unknown, string> {
  const { response, body } = responseBody;
  return response.ok ? E.succeed(body) : E.fail(`${body.message}`);
}
