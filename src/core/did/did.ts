import _ from "es-toolkit/compat";
import { z } from "zod";
import * as ethr from "./ethr";
import * as key from "./key";
import * as nil from "./nil";
import type { Did } from "./types";

export type { Did } from "./types";

/**
 * Parses a DID string into its structured object representation.
 * Supports did:key, did:ethr, and did:nil methods.
 *
 * @param didString - The DID string to parse (e.g., "did:key:zDnae..." or "did:nil:03a1b2c3...")
 * @returns A structured DID object containing method, public key, and other metadata
 * @throws {Error} If the DID method is not supported
 *
 * @example
 * ```typescript
 * import * as did from "#/core/did/did";
 *
 * const parsedDid = did.parse("did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169");
 * console.log(parsedDid.method); // "key"
 * console.log(parsedDid.publicKeyBytes); // Uint8Array(...)
 * ```
 */
export function parse(didString: string): Did {
  if (didString.startsWith("did:key:")) return key.parse(didString);
  if (didString.startsWith("did:ethr:")) return ethr.parse(didString);
  if (didString.startsWith("did:nil:")) return nil.parse(didString);
  throw new Error(`Unsupported Did method for string: ${didString}`);
}

/**
 * Serializes a structured DID object back into its string form.
 *
 * @param did - The structured DID object to serialize
 * @returns The DID as a string
 *
 * @example
 * ```typescript
 * const didString = did.serialize(parsedDid);
 * console.log(didString); // "did:key:zDnae..."
 * ```
 */
export function serialize(did: Did): string {
  return did.didString;
}

/**
 * Validates a signature against a DID's public key.
 *
 * @param did - The DID whose public key will verify the signature
 * @param message - The message that was signed
 * @param signature - The signature to verify
 * @returns True if the signature is valid for the given message and DID
 *
 * @example
 * ```typescript
 * const message = new TextEncoder().encode("Hello world");
 * const signature = keypair.signBytes(message);
 * const did = keypair.toDid();
 *
 * const isValid = did.validateSignature(did, message, signature);
 * console.log(isValid); // true
 * ```
 */
export function validateSignature(
  did: Did,
  message: Uint8Array,
  signature: Uint8Array,
): boolean {
  switch (did.method) {
    case "key":
      return key.validateSignature(did, message, signature);
    case "ethr":
      return ethr.validateSignature(did, message, signature);
    case "nil":
      return nil.validateSignature(did, message, signature);
  }
}

/**
 * Extracts the public key bytes from a DID object, if available.
 * @internal
 */
function getPublicKeyBytes(did: Did): Uint8Array | null {
  if (did.method === "key" || did.method === "nil") {
    return did.publicKeyBytes;
  }
  return null;
}

/**
 * Performs a semantic equality check on two structured DID objects.
 * Compares by public key when available, allowing cross-method comparison.
 *
 * @param a - The first DID to compare
 * @param b - The second DID to compare
 * @returns True if the DIDs represent the same identity
 *
 * @remarks This function provides a powerful capability that may not be immediately obvious:
 * it enables semantic comparison between different DID methods (such as `did:key` and `did:nil`)
 * by comparing their underlying public keys rather than just their string representations.
 * This means that two DIDs with different formats but the same public key will be considered equal,
 * which is essential for interoperability between systems using different DID methods.
 *
 * @example
 * ```typescript
 * const keypair = Keypair.generate();
 * const didKey = keypair.toDid("key");
 * const didNil = keypair.toDid("nil");
 *
 * // Returns true - same underlying public key
 * console.log(did.areEqual(didKey, didNil)); // true
 *
 * // Different formats, same identity
 * const didKeyString = "did:key:zDnae...";
 * const didNilString = "did:nil:03a1b2c3...";
 * console.log(did.areEqual(
 *   did.parse(didKeyString),
 *   did.parse(didNilString)
 * )); // true if same public key
 * ```
 */
export function areEqual(a: Did, b: Did): boolean {
  const pkA = getPublicKeyBytes(a);
  const pkB = getPublicKeyBytes(b);

  // If both have public keys, compare them directly byte-for-byte.
  if (pkA && pkB) {
    return _.isEqual(pkA, pkB);
  }

  // Otherwise, fall back to a structural equality for other DID types (e.g., ethr).
  return _.isEqual(a, b);
}

const DID_EXPRESSION = /^did:.+:.+$/;
export const DidSchema = z
  .string()
  .regex(DID_EXPRESSION, "invalid DID")
  .transform(parse);

/**
 * Creates a DID from raw public key bytes.
 *
 * @param publicKeyBytes - The public key as a Uint8Array
 * @param method - The DID method to use: "key" (default) or "nil"
 * @returns A structured DID object
 *
 * @example
 * ```typescript
 * const publicKeyBytes = new Uint8Array([3, 161, 178, 195, ...]);
 *
 * // Create a did:key (modern format)
 * const modernDid = did.fromPublicKey(publicKeyBytes);
 *
 * // Create a did:nil (legacy format)
 * const legacyDid = did.fromPublicKey(publicKeyBytes, "nil");
 * ```
 */
export function fromPublicKey(
  publicKeyBytes: Uint8Array,
  method: "key" | "nil" = "key",
): Did {
  if (method === "key") {
    return parse(key.fromPublicKeyBytes(publicKeyBytes));
  }
  return parse(nil.fromPublicKeyBytes(publicKeyBytes));
}
