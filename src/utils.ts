import { bytesToHex } from "@noble/hashes/utils";
import { base64url } from "@scure/base";
import { Effect as E, pipe } from "effect";
import { type Schema, type ZodError, z } from "zod";
import { InvalidContentType } from "#/errors";
import type { Keypair } from "#/keypair";
import type { SignedRequest } from "#/nilauth/types";

/**
 * Zod schema for validating hexadecimal strings.
 */
export const HexSchema = z.string().regex(/^[a-fA-F0-9]+$/, "invalid hex");
/** Type for a validated hexadecimal string. */
export type Hex = z.infer<typeof HexSchema>;

/**
 * Converts a UTF-8 string to hexadecimal.
 *
 * The string is first encoded as UTF-8 bytes, then each byte is
 * converted to its hexadecimal representation.
 *
 * @param data - The UTF-8 string to convert.
 * @returns Hexadecimal representation of the UTF-8 encoded bytes.
 * @example
 * toHex("hello") // Returns "68656c6c6f"
 * toHex("🔥") // Returns "f09f94a5" (UTF-8 encoding of emoji)
 */
export function toHex(data: string): Hex {
  const bytes = new TextEncoder().encode(data);
  return bytesToHex(bytes);
}

/**
 * Encodes input as URL-safe base64 without padding.
 *
 * Converts strings to UTF-8 bytes before encoding. The resulting
 * base64url string has padding characters (=) removed for URL safety.
 *
 * @param input - String or byte array to encode.
 * @returns URL-safe base64 encoded string without padding.
 * @example
 * base64UrlEncode("hello") // Returns "aGVsbG8"
 * base64UrlEncode(new Uint8Array([1, 2, 3])) // Returns "AQID"
 */
export function base64UrlEncode(input: string | Uint8Array): string {
  const data =
    typeof input === "string" ? new TextEncoder().encode(input) : input;
  return base64url.encode(data).replace(/=+$/, "");
}

/**
 * Decodes a URL-safe base64 string into a UTF-8 string.
 *
 * Handles both padded and unpadded base64url strings. If input is a
 * Uint8Array, it's first decoded to a string before processing.
 *
 * @param input - Base64url string or bytes to decode.
 * @returns Decoded UTF-8 string.
 * @throws Error if the decoded bytes are not valid UTF-8.
 * @example
 * base64UrlDecode("aGVsbG8") // Returns "hello"
 * base64UrlDecode("aGVsbG8=") // Also returns "hello" (handles padding)
 */
export function base64UrlDecode(input: string | Uint8Array): string {
  const inputStr =
    typeof input === "string" ? input : new TextDecoder().decode(input);
  const bytes = base64UrlDecodeToBytes(inputStr);
  return new TextDecoder().decode(bytes);
}

/**
 * Adds padding to a base64/base64url string if needed.
 *
 * Base64 strings must have a length that's a multiple of 4.
 * This function adds the appropriate number of '=' characters.
 *
 * @param input - Base64 string that may lack padding.
 * @returns Base64 string with proper padding.
 * @internal
 */
function addBase64Padding(input: string): string {
  const padding = (4 - (input.length % 4)) % 4;
  return padding > 0 ? input + "=".repeat(padding) : input;
}

/**
 * Decodes a URL-safe base64 string into raw bytes.
 *
 * Automatically adds padding if needed before decoding. Useful when
 * you need the raw binary data rather than a UTF-8 string.
 *
 * @param input - Base64url string to decode.
 * @returns Decoded bytes as Uint8Array.
 * @example
 * base64UrlDecodeToBytes("AQID") // Returns Uint8Array([1, 2, 3])
 */
export function base64UrlDecodeToBytes(input: string): Uint8Array {
  // Add padding if needed (base64url often omits padding)
  const padded = addBase64Padding(input);

  // Decode using @scure/base which handles padding properly
  return base64url.decode(padded);
}

/**
 * Generates consecutive pairs for a given array.
 * For example: [a, b, c] => [[a, b], [b, c]]
 * @param input - The input array.
 * @returns Array of consecutive pairs.
 */
export function pairwise<T>(input: Array<T>): Array<Array<T>> {
  return input.slice(0, -1).map((item, index) => [item, input[index + 1]]);
}

/**
 * Generates cryptographically secure random bytes using Web Crypto API.
 * @param size - Number of random bytes to generate.
 * @returns Uint8Array of random bytes.
 * @throws Error if Web Crypto API is not available.
 */
export function randomBytes(size: number): Uint8Array {
  const buffer = new Uint8Array(size);
  globalThis.crypto.getRandomValues(buffer);
  return buffer;
}

/**
 * Pipeable combinator to parse the result of an Effect using a Zod schema.
 *
 * @param schema - The Zod schema to use for parsing.
 * @returns A function that takes Effect<unknown, E> and returns Effect<T, E | ZodError>
 */
export function parseWithZodSchema<A, E>(
  schema: Schema,
): (effect: E.Effect<unknown, E>) => E.Effect<A, ZodError | E> {
  return (effect) =>
    effect.pipe(
      E.flatMap((data) =>
        E.try({
          try: () => schema.parse(data),
          catch: (e) => e as ZodError,
        }),
      ),
    );
}

/**
 * Pipeable combinator to parse a Fetch Response as JSON.
 *
 * @returns A function that takes Effect<Response, E> and returns Effect<any, E | InvalidContentType>
 */
export function extractResponseJson<E>() {
  return (
    effect: E.Effect<globalThis.Response, E>,
  ): E.Effect<unknown, E | InvalidContentType> =>
    effect.pipe(
      E.flatMap((response) =>
        E.tryPromise({
          try: () => response.json(),
          catch: (cause) =>
            new InvalidContentType({
              actual: response.headers.get("content-type"),
              expected: "plain/text",
              response,
              cause: cause as Error,
            }),
        }),
      ),
    );
}

/**
 * Pipeable combinator to parse a Fetch Response as text.
 *
 * @returns A function that takes Effect<Response, E> and returns Effect<string, E | InvalidContentType>
 */
export function extractResponseText<E>() {
  return (
    effect: E.Effect<globalThis.Response, E>,
  ): E.Effect<unknown, E | InvalidContentType> =>
    effect.pipe(
      E.flatMap((response) =>
        E.tryPromise({
          try: () => response.text(),
          catch: (cause) =>
            new InvalidContentType({
              actual: response.headers.get("content-type"),
              expected: "application/json",
              response,
              cause: cause as Error,
            }),
        }),
      ),
    );
}

/**
 * Asserts the type of an Effect result at compile time.
 * Used for type narrowing in effectful pipelines.
 *
 * @returns A function that casts the Effect's output type.
 */
export function assertType<B>() {
  return <A, E>(effect: E.Effect<A, E>): E.Effect<B, E> =>
    effect as unknown as E.Effect<B, E>;
}

/**
 * Generates a random nonce as a hexadecimal string.
 * @returns Hexadecimal nonce string.
 */
export function generateNonce(): Hex {
  const bytes = randomBytes(16);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Creates a signed request object from a payload and a keypair.
 *
 * @param payload - The payload to sign.
 * @param keypair - The keypair to use for signing.
 * @returns A SignedRequest object.
 */
export function createSignedRequest(
  payload: Record<string, unknown>,
  keypair: Keypair,
): SignedRequest {
  const stringifiedPayload = JSON.stringify(payload);
  return {
    public_key: keypair.publicKey("hex"),
    signature: keypair.sign(stringifiedPayload, "hex"),
    payload: toHex(stringifiedPayload),
  };
}

/**
 * Unwraps an Effect to a Promise, throwing on failure.
 * If the Effect fails, the error is thrown; otherwise, the value is returned.
 *
 * @param effect - The Effect to unwrap.
 * @returns Promise of the successful value, or throws the error.
 */
export async function unwrapEffect<A, E>(effect: E.Effect<A, E>): Promise<A> {
  const result = await pipe(effect, E.either, E.runPromise);

  if (result._tag === "Right") {
    return result.right;
  }
  throw result.left;
}
