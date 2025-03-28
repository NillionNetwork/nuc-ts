import { secp256k1 } from "@noble/curves/secp256k1";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import { Did, type DidString } from "#/token";

type KeyFormat = "bytes" | "hex";

/**
 * Represents a secp256k1 elliptic curve key pair with secure key handling
 */
export class Keypair {
  readonly #privateKey: Uint8Array;
  readonly #publicKey: Uint8Array;

  /**
   * Creates a Keypair instance from a valid 32-byte private key
   * @param privateKey - The private key as raw bytes
   */
  constructor(privateKey: Uint8Array) {
    this.#privateKey = privateKey;
    this.#publicKey = secp256k1.getPublicKey(privateKey);
  }

  /**
   * Get private key in specified format
   * @param format - Output encoding (default: bytes in an Uint8Array)
   * @returns Private key in requested format
   */
  privateKey(): Uint8Array;
  privateKey(format: "bytes"): Uint8Array;
  privateKey(format: "hex"): string;
  privateKey(format?: KeyFormat): Uint8Array | string {
    return format === "hex"
      ? bytesToHex(this.#privateKey)
      : new Uint8Array(this.#privateKey);
  }

  /**
   * Get public key in specified format
   * @param format - Output encoding (default: bytes in an Uint8Array)
   * @returns Public key in requested format
   */
  publicKey(): Uint8Array;
  publicKey(format: "bytes"): Uint8Array;
  publicKey(format: "hex"): string;
  publicKey(format?: KeyFormat): Uint8Array | string {
    return format === "hex"
      ? bytesToHex(this.#publicKey)
      : new Uint8Array(this.#publicKey);
  }

  /**
   * Returns true if this keypair matches the provided public key
   */
  matchesPublicKey(pk: Uint8Array | string): boolean {
    const compareKey = typeof pk === "string" ? hexToBytes(pk) : pk;
    return Buffer.from(this.publicKey()).equals(Buffer.from(compareKey));
  }

  /**
   * Returns a stringified Did, e.g., did:nil:<public_key_as_hex>
   */
  toDidString(): DidString {
    return new Did(this.#publicKey).toString();
  }

  /**
   * Creates a Keypair from a private key
   * @param privateKey - The private key as hex string or raw bytes
   * @returns New Keypair instance
   */
  static from(privateKey: Uint8Array): Keypair;
  static from(privateKey: string): Keypair;
  static from(privateKey: string | Uint8Array): Keypair {
    const bytes =
      typeof privateKey === "string" ? hexToBytes(privateKey) : privateKey;

    return new Keypair(bytes);
  }

  /**
   * Generates a new cryptographically secure random key pair
   * @returns A new Keypair instance
   */
  static generate(): Keypair {
    return new Keypair(secp256k1.utils.randomPrivateKey());
  }
}
