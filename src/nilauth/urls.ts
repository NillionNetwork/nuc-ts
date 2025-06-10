import type { BlindModule } from "#/nilauth/client";
import type { Hex } from "#/utils";

/**
 * Utility object for constructing Nilauth service endpoint URLs.
 *
 * Each method returns the full URL for a particular Nilauth API endpoint,
 * given a base URL for the Nilauth service.
 */
export const NilauthUrl = {
  about: (base: string) => `${base}/about`,
  health: (base: string) => `${base}/health`,
  nucs: {
    create: (base: string) => `${base}/api/v1/nucs/create`,
    revoke: (base: string) => `${base}/api/v1/revocations/revoke`,
    findRevocations: (base: string) => `${base}/api/v1/revocations/lookup`,
  },
  payments: {
    cost: (base: string, blindModule: BlindModule) =>
      `${base}/api/v1/payments/cost?blind_module=${blindModule}`,
    validate: (base: string) => `${base}/api/v1/payments/validate`,
  },
  subscriptions: {
    status: (base: string, publicKey: Hex, blindModule: BlindModule) =>
      `${base}/api/v1/subscriptions/status?public_key=${publicKey}&blind_module=${blindModule}`,
  },
} as const;
