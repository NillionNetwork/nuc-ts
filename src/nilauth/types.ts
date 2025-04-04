import { Temporal } from "temporal-polyfill";
import z from "zod";
import { NucTokenEnvelopeSchema } from "#/envelope";
import type { TxHash } from "#/payer/types";

export type SignedRequest = {
  public_key: string;
  signature: string;
  payload: string;
};

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

export const SubscriptionDetailsSchema = z
  .object({
    expires_at: z.number(),
    renewable_at: z.number(),
  })
  .transform(({ expires_at, renewable_at }) => ({
    expiresAt: Temporal.Instant.fromEpochSeconds(expires_at),
    renewableAt: Temporal.Instant.fromEpochSeconds(renewable_at),
  }));
export type SubscriptionDetails = z.infer<typeof SubscriptionDetailsSchema>;

export const SubscriptionStatusResponseSchema = z.object({
  subscribed: z.boolean(),
  details: SubscriptionDetailsSchema.nullable(),
});
export type SubscriptionStatusResponse = z.infer<
  typeof SubscriptionStatusResponseSchema
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

export type ValidatePaymentRequest = {
  tx_hash: TxHash;
  payload: string;
  public_key: string;
};
