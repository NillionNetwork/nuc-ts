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
 * Converts a string or object to a hexadecimal string.
 * If input is an object, it is stringified as JSON before conversion.
 *
 * @param input - The string or object to convert.
 * @returns Hexadecimal representation of the input.
 */
export function toHex(input: string | Record<string, unknown>): Hex {
  const data = typeof input === "string" ? input : JSON.stringify(input);
  return Buffer.from(data).toString("hex");
}

/**
 * Encodes input as URL-safe base64.
 * @param input - Data to encode (string or Uint8Array).
 * @returns URL-safe base64 encoded string.
 */
export function base64UrlEncode(input: string | Uint8Array): string {
  // Convert input to Uint8Array if it's a string
  const data =
    typeof input === "string" ? new TextEncoder().encode(input) : input;

  // Convert Uint8Array to binary string
  const binaryString = [...new Uint8Array(data)]
    .map((byte) => String.fromCharCode(byte))
    .join("");

  // Encode to base64
  const base64 = btoa(binaryString);

  // Make base64 URL-safe
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * Decodes a URL-safe base64 input into a string.
 * @param input - Data to decode.
 * @returns Decoded string.
 */
export function base64UrlDecode(input: string | Uint8Array): string {
  return Buffer.from(base64UrlToBase64(input), "base64").toString();
}

/**
 * Decodes a URL-safe base64 input into a Uint8Array.
 * @param input - Data to decode.
 * @returns Decoded bytes.
 */
export function base64UrlDecodeToBytes(input: string): Uint8Array {
  return new Uint8Array(Buffer.from(base64UrlToBase64(input), "base64"));
}

/**
 * Converts a URL-safe base64 string to standard base64.
 * Pads the string if necessary.
 * @param input - URL-safe base64 string or bytes.
 * @returns Standard base64 string.
 */
function base64UrlToBase64(input: string | Uint8Array): string {
  const base64url =
    typeof input === "string" ? input : Buffer.from(input).toString();
  let base64 = base64url.replace(/-/g, "+").replace(/_/g, "/");
  while (base64.length % 4 !== 0) {
    base64 += "=";
  }
  return base64;
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
  if (typeof globalThis === "undefined") {
    throw new Error("globalThis is not available in this environment");
  }
  if (
    !globalThis.crypto ||
    typeof globalThis.crypto.getRandomValues !== "function"
  ) {
    throw new Error("Web Crypto API is not available in this environment");
  }
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
