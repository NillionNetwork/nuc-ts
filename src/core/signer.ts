import { z } from "zod";
import type { Did } from "#/core/did/types";
import type { Keypair } from "#/core/keypair";

/**
 * Zod schema for validating the NucHeader structure. This is the single source of truth.
 * The NucHeader specifies the token type, algorithm, and payload version, inspired by JWT.
 */
export const NucHeaderSchema = z
  .object({
    typ: z
      .string()
      .optional()
      .describe(
        'The token type and signing protocol (e.g., "nuc", "nuc+eip712"). This field dictates the validation strategy. For legacy tokens, it may be absent.',
      ),
    alg: z
      .string()
      .min(1)
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
    meta: z
      .record(z.string(), z.unknown())
      .optional()
      .describe(
        "**Optional.** A container for metadata required by specific `typ` values.",
      ),
  })
  .strict();

/**
 * The header for a Nuc, derived from the Zod schema.
 */
export type NucHeader = z.infer<typeof NucHeaderSchema>;

/**
 * An abstract signer that can be used to sign Nucs.
 */
export type Signer = {
  readonly header: NucHeader;
  readonly getDid: () => Promise<Did>;
  readonly sign: (data: Uint8Array) => Promise<Uint8Array>;
};

/**
 * A custom error for signing-related failures.
 */
export class SigningError extends Error {
  constructor(
    message: string,
    public readonly algorithm: string,
    public override readonly cause?: unknown,
  ) {
    super(message);
    this.name = "SigningError";
  }
}

/**
 * Predefined header configurations.
 */
export const NucHeaders = {
  /** The modern, preferred header format for v1 Nuc payloads. */
  v1: { typ: "nuc", alg: "ES256K", ver: "1.0.0" },
  /** The legacy header format for backward compatibility. */
  legacy: { alg: "ES256K" },
} as const;

/**
 * Factory for creating Signer instances.
 */
export const Signers = {
  /**
   * Creates a modern Signer from a nuc-ts Keypair.
   * @param keypair The Keypair to use for signing.
   * @returns A Signer instance using the v1 header and did:key format.
   */
  fromKeypair(keypair: Keypair): Signer {
    return {
      header: NucHeaders.v1,
      getDid: async () => keypair.toDid("key"),
      sign: async (data) => keypair.signBytes(data),
    };
  },

  /**
   * Creates a legacy Signer from a nuc-ts Keypair for nilauth compatibility.
   * @param keypair The Keypair to use for signing.
   * @returns A Signer instance that uses the legacy header and did:nil format.
   */
  fromLegacyKeypair(keypair: Keypair): Signer {
    return {
      header: NucHeaders.legacy,
      getDid: async () => keypair.toDid("nil"),
      sign: async (data) => keypair.signBytes(data),
    };
  },
};
