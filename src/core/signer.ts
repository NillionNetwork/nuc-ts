import { hexToBytes } from "@noble/hashes/utils";
import type { TypedDataDomain } from "ethers";
import { z } from "zod";
import * as did from "#/core/did/did";
import * as ethr from "#/core/did/ethr";
import type { Did } from "#/core/did/types";
import { base64UrlDecode } from "#/core/encoding";
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
 * Interface for EIP-712 signers.
 */
export interface Eip712Signer {
  readonly getAddress: () => Promise<string>;
  readonly signTypedData: (
    domain: TypedDataDomain,
    types: Record<string, Array<{ name: string; type: string }>>,
    value: Record<string, unknown>,
  ) => Promise<string>;
}

/**
 * Predefined header configurations.
 */
export const NucHeaders = {
  /** The modern, preferred header format for v1 Nuc payloads. */
  v1: { typ: "nuc", alg: "ES256K", ver: "1.0.0" },
  /** The legacy header format for backward compatibility. */
  legacy: { alg: "ES256K" },
  /** The EIP-712 header format factory for Ethereum wallet signing. */
  v1_eip712: (domain: TypedDataDomain) => ({
    typ: "nuc+eip712",
    alg: "ES256K",
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
          { name: "pol", type: "string" }, // JSON stringified
          { name: "nbf", type: "uint256" },
          { name: "exp", type: "uint256" },
          { name: "nonce", type: "string" },
          { name: "prf", type: "string[]" },
        ],
      },
    },
  }),
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

  /**
   * Creates an EIP-712 Signer for Ethereum wallet signing.
   * @param signer The EIP-712 compatible signer (e.g., ethers Wallet)
   * @param domain The EIP-712 domain parameters
   * @returns A Signer instance that uses EIP-712 signing
   */
  fromEip712(signer: Eip712Signer, domain: TypedDataDomain): Signer {
    const eip712Header = NucHeaders.v1_eip712(domain);
    return {
      header: eip712Header,
      getDid: async () => ethr.fromAddress(await signer.getAddress()),
      sign: async (data: Uint8Array): Promise<Uint8Array> => {
        const payloadString = new TextDecoder().decode(data).split(".")[1];
        const decodedPayload = JSON.parse(base64UrlDecode(payloadString));

        const valueToSign = {
          iss:
            typeof decodedPayload.iss === "string"
              ? decodedPayload.iss
              : did.serialize(decodedPayload.iss),
          aud:
            typeof decodedPayload.aud === "string"
              ? decodedPayload.aud
              : did.serialize(decodedPayload.aud),
          sub:
            typeof decodedPayload.sub === "string"
              ? decodedPayload.sub
              : did.serialize(decodedPayload.sub),
          cmd: decodedPayload.cmd || "",
          pol: JSON.stringify(
            decodedPayload.pol !== undefined ? decodedPayload.pol : [],
          ),
          nbf: decodedPayload.nbf || 0,
          exp: decodedPayload.exp || 0,
          nonce: decodedPayload.nonce || "",
          prf: decodedPayload.prf || [],
        };

        const { types, primaryType } = eip712Header.meta;
        const signatureHex = await signer.signTypedData(
          domain,
          { [primaryType]: types.NucPayload },
          valueToSign,
        );
        // Remove 0x prefix if present and convert to bytes
        const hexString = signatureHex.startsWith("0x")
          ? signatureHex.slice(2)
          : signatureHex;
        return hexToBytes(hexString);
      },
    };
  },
};
