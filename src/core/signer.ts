import { hexToBytes } from "@noble/hashes/utils.js";
import type { TypedDataDomain } from "ethers";
import { type NucHeader, NucHeaders, NucHeaderType } from "#/nuc/header";
import { Payload } from "#/nuc/payload";
import { Did } from "./did/did";
import * as ethr from "./did/ethr";
import { base64UrlDecode } from "./encoding";
import type { Keypair } from "./keypair";

export const Headers = {
  legacy: { alg: "ES256K" },
  v1: { typ: NucHeaderType.NATIVE, alg: "ES256K", ver: "1.0.0" },
  v1_eip712: (_domain: TypedDataDomain) => ({
    typ: NucHeaderType.EIP712,
    // ...
  }),
} as const;

/**
 * An abstract signer that can be used to sign Nucs.
 */
export type Signer = {
  readonly header: NucHeader;
  readonly getDid: () => Promise<Did>;
  readonly sign: (data: Uint8Array) => Promise<Uint8Array>;
};

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

export namespace Signer {
  /**
   * Creates a modern Signer from a nuc-ts Keypair.
   * @param keypair The Keypair to use for signing.
   * @returns A Signer instance using the v1 header and did:key format.
   */
  export function fromKeypair(keypair: Keypair): Signer {
    return {
      header: NucHeaders.v1,
      getDid: async () => keypair.toDid("key"),
      sign: async (data) => keypair.signBytes(data),
    };
  }

  /**
   * Creates a legacy Signer from a nuc-ts Keypair for nilauth compatibility.
   * @param keypair The Keypair to use for signing.
   * @returns A Signer instance that uses the legacy header and did:nil format.
   * @deprecated This will be removed in version 0.3.0. Use `fromKeypair` instead.
   */
  export function fromLegacyKeypair(keypair: Keypair): Signer {
    console.warn(
      "DEPRECATION WARNING: `Signer.fromLegacyKeypair` is deprecated and will be removed in the next major version.. Use `Signer.fromKeypair` instead.",
    );

    return {
      header: NucHeaders.legacy,
      getDid: async () => keypair.toDid("nil"),
      sign: async (data) => keypair.signBytes(data),
    };
  }

  /**
   * Creates an EIP-712 Signer for Ethereum wallet signing.
   * @param signer The EIP-712 compatible signer (e.g., ethers Wallet)
   * @param domain The EIP-712 domain parameters
   * @returns A Signer instance that uses EIP-712 signing
   */
  export function fromEip712(
    signer: Eip712Signer,
    domain: TypedDataDomain,
  ): Signer {
    const eip712Header = NucHeaders.v1_eip712(domain);
    return {
      header: eip712Header,
      getDid: async () => ethr.fromAddress(await signer.getAddress()),
      sign: async (data: Uint8Array): Promise<Uint8Array> => {
        const payloadString = new TextDecoder().decode(data).split(".")[1];
        const decodedPayload = JSON.parse(base64UrlDecode(payloadString));

        // Parse the payload to ensure it has proper DID objects
        const parsedPayload = Payload.Schema.parse(decodedPayload);

        // Use the canonical conversion function
        const valueToSign = toEip712Payload(parsedPayload);

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
  }
}

type Eip712NucPayload = {
  iss: string;
  aud: string;
  sub: string;
  cmd: string;
  pol: string;
  args: string;
  nbf: number;
  exp: number;
  nonce: string;
  prf: string[];
};

/**
 * Converts a standard Nuc Payload into an EIP-712 compatible format.
 * @internal
 */
export function toEip712Payload(payload: Payload): Eip712NucPayload {
  return {
    iss: Did.serialize(payload.iss),
    aud: Did.serialize(payload.aud),
    sub: Did.serialize(payload.sub),
    cmd: payload.cmd,
    pol: Payload.isDelegationPayload(payload)
      ? JSON.stringify(payload.pol)
      : "[]",
    args: Payload.isInvocationPayload(payload)
      ? JSON.stringify(payload.args)
      : "{}",
    nbf: payload.nbf || 0,
    exp: payload.exp || 0,
    nonce: payload.nonce,
    prf: payload.prf || [],
  };
}
