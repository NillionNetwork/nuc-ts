import z from "zod";
import {
  base64UrlDecode,
  base64UrlDecodeToBytes,
  base64UrlEncode,
} from "#/core/encoding";
import { Envelope, type Nuc } from "#/nuc/envelope";
import { NucHeaderSchema } from "./header";

const INVALID_NUC_STRUCTURE = "invalid Nuc structure";
const INVALID_NUC_HEADER = "invalid Nuc header";

/**
 * Parses a single Nuc token string (the `header.payload.signature` format) into a raw object.
 * @internal
 */
function parseToken(tokenString: string) {
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
 * // Later, decode it back
 * const decoded = Codec.decodeBase64Url(tokenString);
 * ```
 */
export namespace Codec {
  /**
   * Decodes a base64url-encoded token string into an Envelope.
   *
   * Supports both single tokens and chained tokens (separated by '/').
   * Validates the token structure and header format during decoding.
   *
   * @param nucString - The base64url-encoded token string
   * @returns The decoded and validated Envelope
   * @throws {z.ZodError} Token string is empty or contains empty segments
   * @throws {Error} INVALID_NUC_STRUCTURE - Token lacks three-part structure (header.payload.signature)
   * @throws {Error} INVALID_NUC_HEADER - Header algorithm is not "ES256K"
   * @throws {z.ZodError} Decoded structure doesn't match EnvelopeSchema
   * @example
   * ```typescript
   * // Decode a single token
   * const envelope = Codec.decodeBase64Url("eyJhbGc...");
   *
   * // Decode a chained token
   * const chainedEnvelope = Codec.decodeBase64Url("eyJhbGc.../eyJhbGc...");
   * ```
   */
  export function decodeBase64Url(nucString: string): Envelope {
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
