import { secp256k1 } from "@noble/curves/secp256k1.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import type { TypedDataDomain } from "ethers";
import { NUC_EIP712_DOMAIN, type NucHeader, NucHeaders } from "#/nuc/header";
import { Payload } from "#/nuc/payload";
import { Did } from "./did/did";
import * as ethr from "./did/ethr";
import { base64UrlDecode } from "./encoding";

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
   * Generates a new cryptographically secure Signer.
   * @param didMethod The Did method to use. Defaults to "key".
   * @returns A new Signer instance with a random private key.
   */
  export function generate(didMethod: "key" | "nil" = "key"): Signer {
    const privateKey = secp256k1.utils.randomSecretKey();
    return fromPrivateKey(privateKey, didMethod);
  }

  /**
   * Creates a Signer from a private key.
   * @param privateKey The private key as a hex string or a Uint8Array.
   * @param didMethod The Did method to use. Defaults to "key".
   * @returns A new Signer instance.
   */
  export function fromPrivateKey(
    privateKey: string | Uint8Array,
    didMethod: "key" | "nil" = "key",
  ): Signer {
    const privateKeyBytes =
      typeof privateKey === "string" ? hexToBytes(privateKey) : privateKey;
    const publicKeyBytes = secp256k1.getPublicKey(privateKeyBytes);
    const publicKeyHex = bytesToHex(publicKeyBytes);

    if (didMethod === "nil") {
      console.warn(
        'DEPRECATION WARNING: The "nil" DID method is deprecated and will be removed in a future version. Use the "key" method instead.',
      );
      return {
        header: NucHeaders.legacy,
        getDid: async () => Did.fromPublicKey(publicKeyHex, "nil"),
        sign: async (data) =>
          secp256k1.sign(data, privateKeyBytes, {
            prehash: true,
          }) as Uint8Array,
      };
    }

    return {
      header: NucHeaders.v1,
      getDid: async () => Did.fromPublicKey(publicKeyHex, "key"),
      sign: async (data) =>
        secp256k1.sign(data, privateKeyBytes, { prehash: true }) as Uint8Array,
    };
  }

  /**
   * Creates an EIP-712 Signer for Ethereum wallet signing.
   * @param signer The EIP-712 compatible signer (e.g., ethers Wallet)
   * @param domain The optional EIP-712 domain parameters
   * @returns A Signer instance that uses EIP-712 signing
   */
  export function fromWeb3(
    signer: Eip712Signer,
    domain: TypedDataDomain = NUC_EIP712_DOMAIN,
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
