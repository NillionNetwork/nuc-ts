import type { DidKey } from "#/core/did/types";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { base58btc } from "multiformats/bases/base58";

const SECP256K1_PREFIX = new Uint8Array([0xe7, 0x01]);
const KEY_PREFIX = "did:key:";

export function parse(didString: string): DidKey {
  if (!didString.startsWith(KEY_PREFIX)) {
    throw new Error("Invalid did:key format");
  }
  const multibase = didString.slice(KEY_PREFIX.length);
  if (multibase[0] !== "z") {
    throw new Error("Unsupported multibase encoding for did:key");
  }
  const decoded = base58btc.decode(multibase);
  const prefix = decoded.slice(0, 2);
  if (prefix[0] !== SECP256K1_PREFIX[0] || prefix[1] !== SECP256K1_PREFIX[1]) {
    throw new Error("Unsupported multicodec for did:key");
  }

  return {
    didString,
    method: "key",
    multicodec: "secp256k1-pub",
    publicKeyBytes: decoded.slice(2),
    toJSON: () => didString,
  };
}

/**
 * Creates a did:key string from public key bytes.
 * @internal Used for testing
 */
export function fromPublicKeyBytes(publicKeyBytes: Uint8Array): string {
  const prefixedKey = new Uint8Array(SECP256K1_PREFIX.length + publicKeyBytes.length);
  prefixedKey.set(SECP256K1_PREFIX);
  prefixedKey.set(publicKeyBytes, SECP256K1_PREFIX.length);
  return `${KEY_PREFIX}${base58btc.encode(prefixedKey)}`;
}

/**
 * Validates a did:key signature.
 *
 * @param did The did:key Did
 * @param message The message that was signed
 * @param signature The signature to validate
 * @returns True if the message was signed by the provided did.
 */
export function validateSignature(did: DidKey, message: Uint8Array, signature: Uint8Array): boolean {
  return secp256k1.verify(signature, message, did.publicKeyBytes, {
    prehash: true,
  });
}
