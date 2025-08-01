import { z } from "zod";
import type { Did } from "#/core/did/types";
import type { Keypair } from "#/core/keypair";

/**
 * The header for a Nuc, specifying the algorithm and format version.
 */
export interface NucHeader {
  alg: string;
  ver?: string;
}

/**
 * Zod schema for validating the NucHeader structure.
 */
export const NucHeaderSchema = z
  .object({
    alg: z.string().min(1),
    ver: z
      .string()
      .regex(/^\d+\.\d+\.\d+$/, "Version must be in semver format")
      .optional(),
  })
  .strict();

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
 * Factory for creating Signer instances.
 */
export const Signers = {
  /**
   * Creates a Signer from a nuc-ts Keypair.
   * @param keypair The Keypair to use for signing.
   * @returns A Signer instance.
   */
  fromKeypair(keypair: Keypair): Signer {
    return {
      header: { alg: "ES256K", ver: "1.0.0" },
      getDid: async () => keypair.toDid(),
      sign: async (data) => keypair.signBytes(data),
    };
  },

  /**
   * Creates a legacy Signer for nilauth compatibility.
   * @param keypair The Keypair to use for signing.
   * @returns A Signer instance that uses did:nil and an unversioned header.
   */
  fromLegacyKeypair(keypair: Keypair): Signer {
    return {
      header: { alg: "ES256K" },
      getDid: async () => keypair.toDid("nil"),
      sign: async (data) => keypair.signBytes(data),
    };
  },
};
