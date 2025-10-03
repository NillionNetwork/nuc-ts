/**
 * @module nil
 * @deprecated The "nil" Did method is deprecated and will be removed in a future version. Use the "key" method instead.
 */

import { secp256k1 } from "@noble/curves/secp256k1.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import type { DidNil } from "#/core/did/types";

const NIL_PREFIX = "did:nil:";

export function parse(didString: string): DidNil {
  if (!didString.startsWith(NIL_PREFIX)) {
    throw new Error("Invalid did:nil format");
  }
  const hex = didString.slice(NIL_PREFIX.length);
  return {
    didString,
    method: "nil",
    publicKeyBytes: hexToBytes(hex),
    toJSON: () => didString,
  };
}

/**
 * Creates a did:nil string from public key bytes.
 * @internal Used for testing
 */
export function fromPublicKeyBytes(publicKeyBytes: Uint8Array): string {
  return `${NIL_PREFIX}${bytesToHex(publicKeyBytes)}`;
}

/**
 * Validates a did:nil signature.
 *
 * @param did The did:nil Did
 * @param message The message that was signed
 * @param signature The signature to validate
 * @returns True if the message was signed by the provided did.
 */
export function validateSignature(
  did: DidNil,
  message: Uint8Array,
  signature: Uint8Array,
): boolean {
  return secp256k1.verify(signature, message, did.publicKeyBytes, {
    prehash: true,
  });
}
