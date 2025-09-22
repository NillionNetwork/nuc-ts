import { secp256k1 } from "@noble/curves/secp256k1";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import { base58btc } from "multiformats/bases/base58";
import type { Did } from "#/core/did/types";

/**
 * Represents a secp256k1 elliptic curve key pair with a simplified, hex-string based API.
 * Provides methods for key generation, signing, and DID creation.
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
 * // Sign a message
 * const signature = keypair.sign("Hello world");
 *
 * // Get DID representation
 * const did = keypair.toDid(); // did:key format
 * const legacyDid = keypair.toDid("nil"); // did:nil format
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
    return new Keypair(bytes);
  }

  /**
   * Creates a Keypair from private key bytes.
   * @param privateKey - The private key as a Uint8Array
   * @returns A new Keypair instance
   */
  static fromBytes(privateKey: Uint8Array): Keypair {
    return new Keypair(privateKey);
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
    return new Keypair(secp256k1.utils.randomSecretKey());
  }

  readonly #privateKey: Uint8Array;
  readonly #publicKey: Uint8Array;

  /**
   * The constructor is private to enforce creation via the `from` or `generate` static methods.
   * @param privateKey - The private key as raw bytes.
   */
  private constructor(privateKey: Uint8Array) {
    this.#privateKey = privateKey;
    this.#publicKey = secp256k1.getPublicKey(privateKey);
  }

  /**
   * Gets the private key as a hex-encoded string.
   * @returns The private key in hex format
   */
  privateKey(): string {
    return bytesToHex(this.#privateKey);
  }

  /**
   * Gets the public key as a hex-encoded string.
   * @returns The compressed public key in hex format
   */
  publicKey(): string {
    return bytesToHex(this.#publicKey);
  }

  /**
   * Checks if this keypair's public key matches the provided hex string.
   * @param pk - The public key hex string to compare against
   * @returns True if the public keys match
   */
  matchesPublicKey(pk: string): boolean {
    return this.publicKey() === pk;
  }

  /**
   * Creates a DID (Decentralized Identifier) from this keypair's public key.
   * @param format - The DID format to use: "key" (modern) or "nil" (legacy). Defaults to "key"
   * @returns A structured DID object that can be serialized
   * @example
   * ```typescript
   * const keypair = Keypair.generate();
   *
   * // Modern did:key format (default)
   * const modernDid = keypair.toDid();
   * console.log(modernDid.didString); // "did:key:zDnae..."
   *
   * // Legacy did:nil format for backward compatibility
   * const legacyDid = keypair.toDid("nil");
   * console.log(legacyDid.didString); // "did:nil:03a1b2c3..."
   * ```
   */
  toDid(format: "key" | "nil" = "key"): Did {
    switch (format) {
      case "key": {
        const didString = `did:key:${base58btc.encode(
          new Uint8Array([0xe7, 0x01, ...this.#publicKey]),
        )}`;
        return {
          didString,
          method: "key",
          multicodec: "secp256k1-pub",
          publicKeyBytes: this.#publicKey,
          toJSON: () => didString,
        };
      }
      case "nil": {
        const didString = `did:nil:${bytesToHex(this.#publicKey)}`;
        return {
          didString,
          method: "nil",
          publicKeyBytes: this.#publicKey,
          toJSON: () => didString,
        };
      }
    }
  }

  /**
   * Signs a text message using the private key.
   * @param text - The message to sign
   * @returns The hex-encoded signature
   * @example
   * ```typescript
   * const signature = keypair.sign("Hello world");
   * console.log(signature); // "304402..."
   * ```
   */
  sign(text: string): string {
    const dataAsBytes = new TextEncoder().encode(text);
    const signature = this.signBytes(dataAsBytes);
    return bytesToHex(signature);
  }

  /**
   * Signs raw bytes using the private key.
   * @param bytes - The bytes to sign
   * @returns The signature as a Uint8Array
   */
  signBytes(bytes: Uint8Array): Uint8Array {
    return secp256k1.sign(bytes, this.#privateKey, {
      prehash: true,
    });
  }

  /**
   * Gets the raw public key bytes.
   * @returns The compressed public key as a Uint8Array
   */
  publicKeyBytes(): Uint8Array {
    return new Uint8Array(this.#publicKey);
  }

  /**
   * Gets the raw private key bytes.
   * @returns The private key as a Uint8Array
   * @note This is primarily for interoperability with libraries like CosmJS.
   * Prefer using the hex-based methods for general application logic.
   */
  privateKeyBytes(): Uint8Array {
    return new Uint8Array(this.#privateKey);
  }
}
