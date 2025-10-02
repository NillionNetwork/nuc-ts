import { secp256k1 } from "@noble/curves/secp256k1.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import type { TypedDataDomain } from "ethers";
import { base58btc } from "multiformats/bases/base58";
import * as ethr from "#/core/did/ethr";
import type { Did } from "#/core/did/types";
import {
  type Eip712Signer,
  Signer,
  type Signer as SignerType,
} from "#/core/signer";

// Internal discriminated union for Keypair data
type KeypairInternal =
  | {
      readonly type: "native";
      readonly privateKey: Uint8Array;
      readonly publicKey: Uint8Array;
    }
  | {
      readonly type: "web3";
      readonly signer: Eip712Signer;
      readonly address: string;
      readonly domain: TypedDataDomain;
    };

/**
 * Represents a secp256k1 elliptic curve key pair with a simplified, hex-string based API.
 * Provides methods for key generation, signing, and DID creation.
 * Can be instantiated from a private key or a web3 signer.
 *
 * @example
 * ```typescript
 * import { Keypair } from "#/core/keypair";
 *
 * // Generate a new random keypair
 * const keypair = Keypair.generate();
 *
 * // Create from existing private key
 * const imported = Keypair.from("0x1234...");
 *
 * // Create from an ethers.js signer (e.g., from a browser wallet)
 * const web3Keypair = await Keypair.fromEthersSigner(ethersSigner, domain);
 *
 * // Get DID representation
 * const didKey = keypair.toDid(); // did:key format
 * const didEthr = web3Keypair.toDid(); // did:ethr format
 * ```
 */
export class Keypair {
  /**
   * Creates a Keypair from a private key hex string.
   * @param secretKey - The private key as a hex string (with or without "0x" prefix)
   * @returns A new Keypair instance
   * @example
   * ```typescript
   * const keypair = Keypair.from("0x1234567890abcdef...");
   * ```
   */
  static from(secretKey: string): Keypair {
    const bytes = hexToBytes(secretKey);
    return new Keypair({
      type: "native",
      privateKey: bytes,
      publicKey: secp256k1.getPublicKey(bytes),
    });
  }

  /**
   * Creates a Keypair from private key bytes.
   * @param privateKey - The private key as a Uint8Array
   * @returns A new Keypair instance
   */
  static fromBytes(privateKey: Uint8Array): Keypair {
    return new Keypair({
      type: "native",
      privateKey,
      publicKey: secp256k1.getPublicKey(privateKey),
    });
  }

  /**
   * Generates a new cryptographically secure random key pair.
   * @returns A new Keypair instance with random keys
   * @example
   * ```typescript
   * const keypair = Keypair.generate();
   * console.log(keypair.publicKey()); // "03a1b2c3d4..."
   * ```
   */
  static generate(): Keypair {
    const privateKey = secp256k1.utils.randomSecretKey();
    return new Keypair({
      type: "native",
      privateKey,
      publicKey: secp256k1.getPublicKey(privateKey),
    });
  }

  /**
   * Creates a Keypair from an EIP-712 compatible signer (e.g., from ethers.js).
   * This is the recommended way to use the library with browser wallets.
   * @param signer - An EIP-712 compatible signer instance
   * @param domain - The EIP-712 domain for signing Nucs
   * @returns A new Keypair instance backed by the web3 signer
   * @example
   * ```typescript
   * import { ethers } from "ethers";
   *
   * const provider = new ethers.BrowserProvider(window.ethereum);
   * const ethersSigner = await provider.getSigner();
   * const domain = { name: "NUC", version: "1", chainId: 1 };
   * const keypair = await Keypair.fromEthersSigner(ethersSigner, domain);
   * ```
   */
  static async fromEthersSigner(
    signer: Eip712Signer,
    domain: TypedDataDomain,
  ): Promise<Keypair> {
    const address = await signer.getAddress();
    const internal: KeypairInternal = {
      type: "web3",
      signer,
      address,
      domain,
    };
    return new Keypair(internal);
  }

  readonly #internal: KeypairInternal;

  /**
   * The constructor is private to enforce creation via static methods.
   * @param internal - The internal keypair representation.
   */
  private constructor(internal: KeypairInternal) {
    this.#internal = internal;
  }

  /**
   * Gets the private key as a hex-encoded string.
   * @returns The private key in hex format
   * @throws {Error} If the keypair is backed by a web3 signer.
   */
  privateKey(): string {
    if (this.#internal.type === "web3") {
      throw new Error("privateKey is not available for Web3-based keypairs.");
    }
    return bytesToHex(this.#internal.privateKey);
  }

  /**
   * Gets the public key as a hex-encoded string.
   * @returns The compressed public key in hex format
   * @throws {Error} If the keypair is backed by a web3 signer.
   */
  publicKey(): string {
    if (this.#internal.type === "web3") {
      throw new Error(
        "publicKey is not available for Web3-based keypairs. Use toDid() to get the did:ethr identifier.",
      );
    }
    return bytesToHex(this.#internal.publicKey);
  }

  /**
   * Checks if this keypair's public key matches the provided hex string.
   * @param pk - The public key hex string to compare against
   * @returns True if the public keys match
   * @throws {Error} If the keypair is backed by a web3 signer.
   */
  matchesPublicKey(pk: string): boolean {
    if (this.#internal.type === "web3") {
      throw new Error(
        "matchesPublicKey is not available for Web3-based keypairs.",
      );
    }
    return this.publicKey() === pk;
  }

  /**
   * Creates a Did (Decentralized Identifier) from this keypair.
   * - For native keypairs, defaults to "key" method. Supports "key" and "nil".
   * - For web3 keypairs, always returns a "ethr" Did.
   * @param method - The Did method to use. If omitted, a default is used.
   * @returns A structured Did object that can be serialized
   */
  toDid(method?: "key" | "nil" | "ethr"): Did {
    if (this.#internal.type === "web3") {
      if (method && method !== "ethr") {
        throw new Error(
          `Web3-based keypairs only support the "ethr" Did method, but "${method}" was requested.`,
        );
      }
      return ethr.fromAddress(this.#internal.address);
    }

    // Native keypair logic
    const nativeMethod = method || "key";
    if (nativeMethod === "ethr") {
      throw new Error("Native keypairs do not support the 'ethr' Did method.");
    }

    if (nativeMethod === "nil") {
      console.warn(
        'The "did:nil" method is deprecated and will be removed in the next major version. Please use the "did:key" method instead.',
      );
      const didString = `did:nil:${bytesToHex(this.#internal.publicKey)}`;
      return {
        didString,
        method: "nil",
        publicKeyBytes: this.#internal.publicKey,
        toJSON: () => didString,
      };
    }

    // Default to "key"
    const didString = `did:key:${base58btc.encode(
      new Uint8Array([0xe7, 0x01, ...this.#internal.publicKey]),
    )}`;
    return {
      didString,
      method: "key",
      multicodec: "secp256k1-pub",
      publicKeyBytes: this.#internal.publicKey,
      toJSON: () => didString,
    };
  }

  /**
   * Creates a `Signer` instance from this keypair.
   *
   * This is a convenience method for creating a signer that can be used
   * with the `Builder` to sign Nuc tokens.
   *
   * @param didMethod - The Did format the signer should use.
   * @returns A `Signer` instance configured for the specified Did method.
   */
  signer(didMethod?: "key" | "nil" | "ethr"): SignerType {
    if (this.#internal.type === "web3") {
      if (didMethod && didMethod !== "ethr") {
        throw new Error(
          `Web3-based keypairs only support the "ethr" Did method for signers, but "${didMethod}" was requested.`,
        );
      }
      return Signer.fromEip712(this.#internal.signer, this.#internal.domain);
    }

    // Native Keypair logic
    const nativeMethod = didMethod || "key";
    if (nativeMethod === "ethr") {
      throw new Error(
        "Native keypairs do not support the 'ethr' Did method for signers.",
      );
    }
    if (nativeMethod === "nil") {
      return Signer.fromLegacyKeypair(this);
    }
    return Signer.fromKeypair(this);
  }

  /**
   * Signs a text message using the private key.
   * @param text - The message to sign
   * @returns The hex-encoded signature
   * @throws {Error} If the keypair is backed by a web3 signer.
   */
  sign(text: string): string {
    if (this.#internal.type === "web3") {
      throw new Error("sign is not available for Web3-based keypairs.");
    }
    const dataAsBytes = new TextEncoder().encode(text);
    const signature = this.signBytes(dataAsBytes);
    return bytesToHex(signature);
  }

  /**
   * Signs raw bytes using the private key.
   * @param bytes - The bytes to sign
   * @returns The signature as a Uint8Array
   * @throws {Error} If the keypair is backed by a web3 signer.
   */
  signBytes(bytes: Uint8Array): Uint8Array {
    if (this.#internal.type === "web3") {
      throw new Error("signBytes is not available for Web3-based keypairs.");
    }
    return secp256k1.sign(bytes, this.#internal.privateKey, {
      prehash: true,
    });
  }

  /**
   * Gets the raw public key bytes.
   * @returns The compressed public key as a Uint8Array
   * @throws {Error} If the keypair is backed by a web3 signer.
   */
  publicKeyBytes(): Uint8Array {
    if (this.#internal.type === "web3") {
      throw new Error(
        "publicKeyBytes is not available for Web3-based keypairs.",
      );
    }
    return new Uint8Array(this.#internal.publicKey);
  }

  /**
   * Gets the raw private key bytes.
   * @returns The private key as a Uint8Array
   * @throws {Error} If the keypair is backed by a web3 signer.
   */
  privateKeyBytes(): Uint8Array {
    if (this.#internal.type === "web3") {
      throw new Error(
        "privateKeyBytes is not available for Web3-based keypairs.",
      );
    }
    return new Uint8Array(this.#internal.privateKey);
  }
}
