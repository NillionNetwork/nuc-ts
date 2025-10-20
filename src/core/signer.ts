import { secp256k1 } from "@noble/curves/secp256k1.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import type { TypedDataDomain } from "ethers";
import {
  createWalletClient,
  custom,
  type EIP1193Provider,
  type SignTypedDataParameters,
  type WalletClient,
} from "viem";
import { mainnet } from "viem/chains";
import {
  NUC_EIP712_DOMAIN,
  type NucHeader,
  NucHeaderSchema,
  NucHeaders,
} from "#/nuc/header";
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
   * @returns A Signer instance that uses EIP-712 signing
   */
  export function fromWeb3(signer: Eip712Signer): Signer {
    return {
      // The Builder constructs the correct header and passes it into `sign`, so here we return a placeholder header
      header: NucHeaders.v1_eip712_delegation(NUC_EIP712_DOMAIN),
      getDid: async () => ethr.fromAddress(await signer.getAddress()),
      sign: async (data: Uint8Array): Promise<Uint8Array> => {
        // The `data` is `rawHeader.rawPayload`. We must parse the header from it.
        const [rawHeader, payloadString] = new TextDecoder()
          .decode(data)
          .split(".");
        if (!rawHeader || !payloadString) {
          throw new SigningError(
            "Invalid data format for EIP-712 signing",
            "ES256K",
          );
        }

        const header = NucHeaderSchema.parse(
          JSON.parse(base64UrlDecode(rawHeader)),
        );
        const { meta } = header;

        if (!meta || !meta.domain || !meta.types || !meta.primaryType) {
          throw new SigningError(
            "EIP-712 metadata missing from header",
            "ES256K",
          );
        }

        const decodedPayload = JSON.parse(base64UrlDecode(payloadString));

        // Parse the payload to ensure it has proper DID objects
        const parsedPayload = Payload.Schema.parse(decodedPayload);

        // Use the canonical conversion function
        const valueToSign = toEip712Payload(parsedPayload);

        // Use the domain, types, and primaryType from the parsed header.
        const domain = meta.domain as TypedDataDomain;
        const types = meta.types as Record<
          string,
          Array<{ name: string; type: string }>
        >;
        const primaryType = meta.primaryType as string;
        const signatureHex = await signer.signTypedData(
          domain,
          { [primaryType]: types[primaryType] },
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

  /**
   * Creates a Signer instance from a browser-based Eip-1193 provider (e.g., window.ethereum).
   *
   * This simplifies integration with browser wallets by wrapping a viem WalletClient and adapting
   * it to the Signer interface.
   *
   * @param provider The Eip-1193 compatible provider, typically `window.ethereum`.
   * @param options Optional account address to use. If not provided, it will be requested from the wallet.
   * @returns A Promise that resolves to a new `Signer` instance.
   * @throws If the provider is not available or the user rejects the connection request.
   */
  export async function fromEip1193Provider(
    provider: EIP1193Provider,
    options?: { account?: `0x${string}` },
  ): Promise<Signer> {
    const client: WalletClient = createWalletClient({
      chain: mainnet, // Nuc Eip-712 signatures are chain-agnostic but viem requires one. Mainnet is a safe default.
      transport: custom(provider),
    });

    const [account] = options?.account
      ? [options.account]
      : await client.requestAddresses();

    if (!account) {
      throw new Error(
        "Failed to get address from provider. User may have rejected the request.",
      );
    }

    const eip712SignerAdapter: Eip712Signer = {
      getAddress: async () => account,
      signTypedData: async (domain, types, value) => {
        const primaryType = Object.keys(types)[0];
        return client.signTypedData({
          account,
          domain: domain as SignTypedDataParameters["domain"],
          types,
          primaryType,
          message: value as Record<string, unknown>,
        });
      },
    };

    return Signer.fromWeb3(eip712SignerAdapter);
  }
}

type Eip712DelegationPayload = {
  iss: string;
  aud: string;
  sub: string;
  cmd: string;
  pol: string;
  nbf: number;
  exp: number;
  nonce: string;
  prf: string[];
};

type Eip712InvocationPayload = {
  iss: string;
  aud: string;
  sub: string;
  cmd: string;
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
export function toEip712Payload(
  payload: Payload,
): Eip712DelegationPayload | Eip712InvocationPayload {
  const common = {
    iss: Did.serialize(payload.iss),
    aud: Did.serialize(payload.aud),
    sub: Did.serialize(payload.sub),
    cmd: payload.cmd,
    nbf: payload.nbf ?? 0,
    exp: payload.exp ?? 0,
    nonce: payload.nonce,
    prf: payload.prf ?? [],
  };
  if (Payload.isDelegationPayload(payload)) {
    return {
      ...common,
      pol: JSON.stringify(payload.pol),
    };
  }
  return {
    ...common,
    args: JSON.stringify(payload.args),
  };
}
