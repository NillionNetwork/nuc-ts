import type { TypedDataDomain } from "ethers";
import { z } from "zod";

/**
 * Nuc encoding types.
 *
 * @example
 * ```jsonc
 * { "typ": "nuc" } // Native using the multibase Did encoding
 * { "typ": "nuc+eip712" } // Uses the signed types EIP
 * ```
 */
export const NucHeaderType = {
  NATIVE: "nuc",
  EIP712: "nuc+eip712",
} as const;

/**
 * Nuc algorithm types.
 *
 * @example
 * ```jsonc
 * { "alg": "ES256k" }
 * ```
 */
export const NucHeaderAlgorithm = {
  Es256k: "ES256K",
} as const;

/**
 * Zod schema for validating the NucHeader structure. This is the single source of truth.
 * The NucHeader specifies the token type, algorithm, and payload version, inspired by JWT.
 */
export const NucHeaderSchema = z
  .object({
    typ: z
      .enum([NucHeaderType.NATIVE, NucHeaderType.EIP712])
      .optional()
      .describe(
        'The token type and signing protocol (e.g., "nuc", "nuc+eip712"). This field dictates the validation strategy. For legacy tokens, it may be absent.',
      ),
    alg: z
      .enum([NucHeaderAlgorithm.Es256k])
      .describe(
        '**Required.** The cryptographic algorithm used for the signature (e.g., "ES256K").',
      ),
    ver: z
      .string()
      .regex(/^\d+\.\d+\.\d+$/, "Version must be in semver format")
      .optional()
      .describe(
        "**Optional.** The semantic version of the Nuc payload specification.",
      ),
    met: z
      .record(z.string(), z.unknown())
      .optional()
      .describe(
        "**Optional.** A container for metadata required by specific `typ` values.",
      ),
  })
  .strict();

export type NucHeader = z.infer<typeof NucHeaderSchema>;

/**
 * The default EIP-712 domain for signing Nuc payloads.
 * This is used for creating signatures with Web3 wallets.
 */
export const NUC_EIP712_DOMAIN: TypedDataDomain = {
  name: "NUC",
  version: "1",
  chainId: 1,
};

/**
 * Predefined header configurations.
 */
export const NucHeaders = {
  /** The legacy header format for backward compatibility. */
  legacy: { alg: NucHeaderAlgorithm.Es256k },
  /** The header format for v1 Nuc payloads. */
  v1: {
    typ: NucHeaderType.NATIVE,
    alg: NucHeaderAlgorithm.Es256k,
    ver: "1.0.0",
  },
  /** The EIP-712 format for Ethereum wallet signing. */
  v1_eip712: (domain: TypedDataDomain) => ({
    typ: NucHeaderType.EIP712,
    alg: NucHeaderAlgorithm.Es256k,
    ver: "1.0.0",
    meta: {
      domain,
      primaryType: "NucPayload",
      types: {
        NucPayload: [
          { name: "iss", type: "string" },
          { name: "aud", type: "string" },
          { name: "sub", type: "string" },
          { name: "cmd", type: "string" },
          { name: "pol", type: "string" },
          { name: "args", type: "string" },
          { name: "nbf", type: "uint256" },
          { name: "exp", type: "uint256" },
          { name: "nonce", type: "string" },
          { name: "prf", type: "string[]" },
        ],
      },
    },
  }),
} as const;
