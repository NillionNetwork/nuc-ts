import { hexToBytes } from "@noble/hashes/utils.js";
import _ from "es-toolkit/compat";
import { z } from "zod";
import * as ethr from "./ethr";
import * as key from "./key";
import * as nil from "./nil";
import type { Did as DidType } from "./types";

export type Did = DidType;

export namespace Did {
  /**
   * Parses a Did string into its structured object representation.
   * Supports did:key, did:ethr, and did:nil methods.
   *
   * @param didString - The Did string to parse (e.g., "did:key:zDnae..." or "did:nil:03a1b2c3...")
   * @returns A structured Did object containing method, public key, and other metadata
   * @throws {Error} If the Did method is not supported
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
   * Serializes a structured Did object back into its string form.
   *
   * @param did - The structured Did object to serialize
   * @returns The Did as a string
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
   * Performs a semantic equality check on two structured Did objects.
   * For Dids with public keys (key, nil), this function compares the underlying
   * public keys, allowing for cross-method comparison. For other types,
   * it falls back to a structural equality check.
   *
   * @param a - The first Did to compare
   * @param b - The second Did to compare
   * @returns True if the Dids represent the same identity
   *
   * @example
   * ```typescript
   * const privateKey = new Uint8Array(32);
   * crypto.getRandomValues(privateKey);
   * const didKey = await Signer.fromPrivateKey(privateKey, "key").getDid();
   * const didNil = await Signer.fromPrivateKey(privateKey, "nil").getDid();
   * console.log(Did.areEqual(didKey, didNil)); // true
   * ```
   */
  export function areEqual(a: Did, b: Did): boolean {
    // Handle ethr by case-insensitive string comparison
    if (a.method === "ethr" && b.method === "ethr") {
      return a.address.toLowerCase() === b.address.toLowerCase();
    }

    // Handle public key based Dids (key, nil) by comparing public keys
    const pkA = getPublicKeyBytes(a);
    const pkB = getPublicKeyBytes(b);

    if (pkA && pkB) {
      return _.isEqual(pkA, pkB);
    }

    // Otherwise, fall back to a structural equality for other Did types (e.g., ethr).
    return _.isEqual(a, b);
  }

  /**
   * Creates a Did from a public key hex string.
   *
   * @param publicKey - The public key as a hex string
   * @param method - The Did method to use: "key" (default) or "nil"
   * @returns A structured Did object
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
    if (method === "nil") {
      console.warn(
        'DEPRECATION WARNING: The "nil" Did method is deprecated and will be removed in a future version. Use the "key" method instead.',
      );
    }

    const publicKeyBytes = hexToBytes(publicKey);
    if (method === "key") {
      return parse(key.fromPublicKeyBytes(publicKeyBytes));
    }
    return parse(nil.fromPublicKeyBytes(publicKeyBytes));
  }

  const DID_EXPRESSION = /^did:.+:.+$/;

  /**
   * Zod schema for parsing and validating Did strings.
   *
   * Validates that a string matches the Did format (did:method:identifier)
   * and automatically transforms it into a structured Did object.
   *
   * @example
   * ```typescript
   * import { Did } from "@nillion/nuc";
   *
   * // Use in Zod schemas
   * const MySchema = z.object({
   *   issuer: Did.Schema,
   *   audience: Did.Schema
   * });
   *
   * // Parse and validate a Did string
   * const did = Did.Schema.parse("did:key:zDnae...");
   * ```
   */
  export const Schema = z
    .string()
    .regex(DID_EXPRESSION, "invalid Did")
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
