import { randomBytes } from "node:crypto";
import { secp256k1 } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha256";
import { Effect as E, pipe } from "effect";
import { Temporal } from "temporal-polyfill";
import z from "zod";
import { NucTokenEnvelopeSchema } from "#/envelope";
import type { Payer } from "#/payer/client";
import type { TxHash } from "#/payer/types";

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

export const TokenMintResponseSchema = z.object({
  token: NucTokenEnvelopeSchema,
});
export type TokenMintResponse = z.infer<typeof TokenMintResponseSchema>;

export const PaySubscriptionResponseSchema = z.null();
export type PaySubscriptionResponse = z.infer<
  typeof PaySubscriptionResponseSchema
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
      E.catchAll((e) => E.fail(e.cause)),
      E.runPromise,
    );
  }

  async requestToken(key: Uint8Array): Promise<TokenMintResponse> {
    const aboutResponse = await this.about();

    const payload = JSON.stringify({
      nonce: randomBytes(16).toString("hex"),
      target_public_key: aboutResponse.publicKey,
      expires_at: Temporal.Now.instant().add({ seconds: 60 }).epochSeconds,
    });

    const signature = secp256k1.sign(
      new Uint8Array(Buffer.from(payload)),
      key,
      { prehash: true },
    );
    const request = {
      public_key: Buffer.from(secp256k1.getPublicKey(key)).toString("hex"),
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
        E.try(() => TokenMintResponseSchema.parse(response)),
      ),
      E.catchAll((e) => E.fail(e.cause)),
      E.runPromise,
    );
  }

  async paySubscription(
    publicKey: string,
    payer: Payer,
  ): Promise<PaySubscriptionResponse> {
    const buildPayload = (aboutResponse: NilauthAboutResponse) => {
      const payload = JSON.stringify({
        nonce: randomBytes(16).toString("hex"),
        service_public_key: aboutResponse.publicKey,
      });
      return {
        payload: Buffer.from(payload).toString("hex"),
        hash: sha256(payload),
      };
    };

    type ValidatePaymentRequest = {
      tx_hash: TxHash;
      payload: string;
      public_key: string;
    };
    const validatePayment = (request: ValidatePaymentRequest) =>
      fetchWithTimeout(
        `${this.baseUrl}/api/v1/payments/validate`,
        this.timeout,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(request),
        },
      );

    return pipe(
      E.tryPromise(() => this.about()),
      E.map(buildPayload),
      E.flatMap(({ payload, hash }) =>
        pipe(
          // TODO assign the correct value later
          E.tryPromise(() => payer.pay(hash, 1)),
          E.map((txHash) => ({ payload, txHash })),
        ),
      ),
      E.andThen(({ payload, txHash }) => ({
        tx_hash: txHash,
        payload,
        public_key: publicKey,
      })),
      E.andThen(validatePayment),
      E.catchAll((e) => E.fail(e.cause)),
      E.flatMap((response) =>
        E.try(() => PaySubscriptionResponseSchema.parse(response)),
      ),
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
    E.andThen(raiseForStatus),
    E.andThen((response) => response.json()),
    E.runPromise,
  );

  const timeoutPromise = new Promise((_, reject) =>
    setTimeout(() => reject(new Error("timeout")), timeout),
  );

  return Promise.race([fetchPromise, timeoutPromise]);
}

function raiseForStatus(response: Response): E.Effect<Response, Error> {
  if (!response.ok) {
    return E.fail(new Error(`${response.status}`));
  }
  return E.succeed(response);
}
