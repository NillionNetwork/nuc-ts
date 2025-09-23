import { z } from "zod";
import { Codec } from "#/nuc/codec";

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
    timestamp: new Date(timestamp).getTime(),
  }));

export const NilauthAboutResponseSchema = z
  .object({
    started: z.string(),
    public_key: z.string(),
    build: BuildSchema,
  })
  .transform(({ started, public_key, build }) => ({
    started: new Date(started).getTime(),
    publicKey: public_key,
    build,
  }));
export type NilauthAboutResponse = z.output<typeof NilauthAboutResponseSchema>;

export const ValidatePaymentResponseSchema = z.null().transform(() => {});
export type ValidatePaymentResponse = z.infer<
  typeof ValidatePaymentResponseSchema
>;

export const SubscriptionCostResponseSchema = z
  .object({
    cost_unils: z.number(),
  })
  .transform(({ cost_unils }) => cost_unils);
export type SubscriptionCostResponse = z.output<
  typeof SubscriptionCostResponseSchema
>;

export const SubscriptionDetailsSchema = z
  .object({
    expires_at: z.number(),
    renewable_at: z.number(),
  })
  .transform(({ expires_at, renewable_at }) => ({
    expiresAt: expires_at * 1000,
    renewableAt: renewable_at * 1000,
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
  token: z.string().transform(Codec.decodeBase64Url),
});
export type CreateTokenResponse = z.infer<typeof CreateTokenResponseSchema>;

export const RevokedTokenSchema = z
  .object({
    token_hash: z.string(),
    revoked_at: z.number(),
  })
  .transform(({ token_hash, revoked_at }) => ({
    tokenHash: token_hash,
    revokedAt: revoked_at * 1000,
  }));
export type RevokedToken = z.output<typeof RevokedTokenSchema>;

export const LookupRevokedTokenResponseSchema = z.object({
  revoked: z.array(RevokedTokenSchema),
});
export type LookupRevokedTokenResponse = z.infer<
  typeof LookupRevokedTokenResponseSchema
>;
