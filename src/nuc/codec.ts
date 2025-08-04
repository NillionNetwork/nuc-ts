import { z } from "zod";
import {
  base64UrlDecode,
  base64UrlDecodeToBytes,
  base64UrlEncode,
} from "#/core/encoding";
import { Signer } from "#/core/signer";
import { Envelope, type Nuc } from "#/nuc/envelope";

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
  const parseResult = Signer.HeaderSchema.safeParse(headerJson);
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

export namespace Codec {
  /**
   * Decodes a base64url-encoded NUC token string into an Envelope structure.
   * Supports both single tokens and chained tokens (separated by '/').
   *
   * @param nucString - The base64url-encoded token string, potentially containing multiple tokens separated by '/'
   * @returns The decoded and validated Envelope containing the token and any proof tokens
   *
   * @throws {z.ZodError} If the token string is empty or contains empty segments
   * @throws {Error} INVALID_NUC_STRUCTURE - If a token doesn't have the expected three-part structure (header.payload.signature)
   * @throws {Error} INVALID_NUC_HEADER - If the header algorithm is not "ES256K"
   * @throws {z.ZodError} If the decoded structure doesn't match the EnvelopeSchema
   *
   * @example
   * ```typescript
   * import { Codec } from "#/nuc/codec";
   *
   * // Decode a single token
   * const envelope = Codec.decodeBase64Url("eyJhbGc...")
   *
   * // Decode a chained token
   * const chainedEnvelope = Codec.decodeBase64Url("eyJhbGc.../eyJhbGc...")
   * ```
   */
  export function decodeBase64Url(nucString: string): Envelope {
    const parts = nucString.split("/");

    if (!parts.every(Boolean)) {
      throw new z.ZodError([
        {
          code: z.ZodIssueCode.custom,
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
          code: z.ZodIssueCode.custom,
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
   * Serializes an Envelope back into a base64url-encoded token string.
   * If the envelope contains proofs, they will be chained using '/' separators.
   *
   * @param envelope - The Envelope to serialize
   * @returns The base64url-encoded token string, with proofs chained using '/'
   *
   * @example
   * ```typescript
   * import { Codec } from "#/nuc/codec";
   * import { Builder } from "#/nuc/builder";
   *
   * const envelope = Builder.invocation()
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
