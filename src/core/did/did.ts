import { hexToBytes } from "@noble/hashes/utils";
import _ from "es-toolkit/compat";
import { z } from "zod";
import * as ethr from "./ethr";
import * as key from "./key";
import * as nil from "./nil";
import type { Did as DidType } from "./types";

export type Did = DidType;

export namespace Did {
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
   * import { Did } from "#/core/did/did";
   *
   * const parsedDid = Did.parse("did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169");
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
   * const didString = Did.serialize(parsedDid);
   * console.log(didString); // "did:key:zDnae..."
   * ```
   */
  export function serialize(did: Did): string {
    return did.didString;
  }

  /**
   * Performs a semantic equality check on two structured DID objects.
   * For DIDs with public keys (key, nil), this function compares the underlying
   * public keys, allowing for cross-method comparison. For other types,
   * it falls back to a structural equality check.
   *
   * @param a - The first DID to compare
   * @param b - The second DID to compare
   * @returns True if the DIDs represent the same identity
   *
   * @example
   * ```typescript
   * const keypair = Keypair.generate();
   * const didKey = keypair.toDid("key");
   * const didNil = keypair.toDid("nil");
   * console.log(Did.areEqual(didKey, didNil)); // true
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

  /**
   * Creates a DID from a public key hex string.
   *
   * @param publicKey - The public key as a hex string
   * @param method - The DID method to use: "key" (default) or "nil"
   * @returns A structured DID object
   *
   * @example
   * ```typescript
   * const publicKey = "03a1b2c3...";
   *
   * // Create a did:key (modern format)
   * const modernDid = Did.fromPublicKey(publicKey);
   *
   * // Create a did:nil (legacy format)
   * const legacyDid = Did.fromPublicKey(publicKey, "nil");
   * ```
   */
  export function fromPublicKey(
    publicKey: string,
    method: "key" | "nil" = "key",
  ): Did {
    const publicKeyBytes = hexToBytes(publicKey);
    if (method === "key") {
      return parse(key.fromPublicKeyBytes(publicKeyBytes));
    }
    return parse(nil.fromPublicKeyBytes(publicKeyBytes));
  }

  const DID_EXPRESSION = /^did:.+:.+$/;
  export const Schema = z
    .string()
    .regex(DID_EXPRESSION, "invalid DID")
    .transform(parse);
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
