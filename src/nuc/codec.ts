import { base64UrlDecode, base64UrlDecodeToBytes, base64UrlEncode } from "#/core/encoding";
import { Log } from "#/core/logger";
import { Envelope, type Nuc } from "#/nuc/envelope";
import z from "zod";

import { NucHeaderSchema } from "./header";

const INVALID_NUC_STRUCTURE = "invalid Nuc structure";
const INVALID_NUC_HEADER = "invalid Nuc header";

/**
 * Parses a single Nuc token string (the `header.payload.signature` format) into a raw object.
 * @internal
 */
function parseToken(tokenString: string): {
  rawHeader: string;
  rawPayload: string;
  signature: Uint8Array;
  payload: unknown;
} {
  const parts = tokenString.split(".");
  if (parts.length !== 3) {
    throw new Error(INVALID_NUC_STRUCTURE);
  }

  const [rawHeader, rawPayload, rawSignature] = parts;

  const headerJson = JSON.parse(base64UrlDecode(rawHeader));
  const parseResult = NucHeaderSchema.safeParse(headerJson);
  if (!parseResult.success) {
    throw new Error(INVALID_NUC_HEADER, { cause: parseResult.error });
  }

  const token = JSON.parse(base64UrlDecode(rawPayload));
  const signature = base64UrlDecodeToBytes(rawSignature);

  // Return a plain object, not a parsed NucSchema object.
  return {
    rawHeader,
    rawPayload,
    signature,
    payload: token,
  };
}

/**
 * Serializes a single decoded token back into its Nuc string format.
 * @internal
 */
function serializeToken(nuc: Nuc): string {
  const signature = base64UrlEncode(nuc.signature);
  return `${nuc.rawHeader}.${nuc.rawPayload}.${signature}`;
}

/**
 * Provides encoding and decoding utilities for NUC tokens.
 *
 * The Codec namespace handles the serialization and deserialization of
 * NUC token envelopes to and from base64url-encoded strings suitable
 * for network transmission.
 *
 * @example
 * ```typescript
 * import { Codec, Builder } from "@nillion/nuc";
 *
 * // Create and serialize a token
 * const envelope = await Builder.delegation()
 *   .audience(audienceDid)
 *   .subject(subjectDid)
 *   .command("/nil/db")
 *   .build(keypair);
 *
 * const tokenString = Codec.serializeBase64Url(envelope);
 *
 * // Later, parse and validate it
 * const decoded = Validator.parse(tokenString, {
 *   rootIssuers: ["did:key:..."]
 * });
 * ```
 */
export namespace Codec {
  /**
   * [UNSAFE] Decodes a base64url-encoded token string into an Envelope without
   * performing any signature or structural validation.
   *
   * @internal
   * @private
   * @warning This function is for internal use and testing only. It does NOT
   *   validate the token's signature, expiration, or chain of trust.
   *   Always use `Validator.parse()` to securely parse and validate tokens.
   *
   * @param nucString - The base64url-encoded token string
   * @returns The decoded but **unvalidated** Envelope
   */
  export function _unsafeDecodeBase64Url(nucString: string): Envelope {
    Log.warn(
      "Using Codec._unsafeDecodeBase64Url. The decoded token is NOT validated. Use Validator.parse() for safe token processing.",
    );
    const parts = nucString.split("/");

    if (!parts.every(Boolean)) {
      throw new z.ZodError([
        {
          code: "custom",
          path: [],
          message: "empty token",
          input: nucString,
        },
      ]);
    }

    const tokens = parts.map(parseToken);

    if (tokens.length === 0) {
      throw new z.ZodError([
        {
          code: "custom",
          path: [],
          message: "no tokens in envelope",
          input: nucString,
        },
      ]);
    }

    // Validate the final envelope structure
    return Envelope.Schema.parse({
      nuc: tokens[0],
      proofs: tokens.slice(1),
    });
  }

  /**
   * Serializes an Envelope into a base64url-encoded token string.
   *
   * Converts the envelope structure back to a transmittable string format.
   * Multiple tokens in the proof chain are joined with '/' separators.
   *
   * @param envelope - The Envelope to serialize
   * @returns The base64url-encoded token string
   * @example
   * ```typescript
   * const envelope = await Builder.invocation()
   *   .audience(audienceDid)
   *   .subject(subjectDid)
   *   .command("/db/read")
   *   .build(keypair);
   *
   * const tokenString = Codec.serializeBase64Url(envelope);
   * // Result: "eyJhbGc..." (or "eyJhbGc.../eyJhbGc..." if chained)
   * ```
   */
  export function serializeBase64Url(envelope: Envelope): string {
    const tokens = [envelope.nuc, ...envelope.proofs];
    return tokens.map(serializeToken).join("/");
  }
}
