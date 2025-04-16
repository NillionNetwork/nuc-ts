import { Temporal } from "temporal-polyfill";
import z from "zod";
import { NucTokenEnvelopeSchema } from "#/envelope";

const PUBLIC_KEY_LENGTH = 66;

export const PublicKeySchema = z
  .string()
  .length(PUBLIC_KEY_LENGTH)
  .brand("PublicKey");

export type PublicKey = z.infer<typeof PublicKeySchema>;

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
    public_key: PublicKeySchema,
    build: BuildSchema,
  })
  .transform(({ started, public_key, build }) => ({
    started: Temporal.Instant.from(started),
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
export type RevokedToken = z.output<typeof RevokedTokenSchema>;

export const LookupRevokedTokenResponseSchema = z.object({
  revoked: z.array(RevokedTokenSchema),
});
export type LookupRevokedTokenResponse = z.output<
  typeof LookupRevokedTokenResponseSchema
>;
