import { z } from "zod";

export const HexSchema = z.string().regex(/^[a-fA-F0-9]+$/, "invalid hex");
export type Hex = z.infer<typeof HexSchema>;

export function toHex(input: string | Record<string, unknown>): Hex {
  const data = typeof input === "string" ? input : JSON.stringify(input);
  return Buffer.from(data).toString("hex");
}

/**
 * Encode URL safe base64.
 * @param input data to be encoded.
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
 * Decode a URL safe base64 input into a string.
 * @param input data to be decoded
 */
export function base64UrlDecode(input: string | Uint8Array): string {
  return Buffer.from(base64UrlToBase64(input), "base64").toString();
}

/**
 * Decode a URL safe base64 input into a Uint8Array.
 * @param input data to be encoded.
 */
export function base64UrlDecodeToBytes(input: string): Uint8Array {
  return new Uint8Array(Buffer.from(base64UrlToBase64(input), "base64"));
}

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
 * @param input array that is used as input.
 */
export function pairwise<T>(input: Array<T>): Array<Array<T>> {
  return input.slice(0, -1).map((item, index) => [item, input[index + 1]]);
}

/**
 * Generate random bytes using Web Crypto API
 * @param size the number of random bytes to generate
 * @returns An array of random bytes
 * @throws Error if globalThis or crypto.getRandomValues is not available
 */
export function randomBytes(size: number): Uint8Array {
  // Check if globalThis is available
  if (typeof globalThis === "undefined") {
    throw new Error("globalThis is not available in this environment");
  }

  // Check if crypto API is available
  if (
    !globalThis.crypto ||
    typeof globalThis.crypto.getRandomValues !== "function"
  ) {
    throw new Error("Web Crypto API is not available in this environment");
  }

  // Use Web Crypto API to generate random bytes
  const buffer = new Uint8Array(size);
  globalThis.crypto.getRandomValues(buffer);
  return buffer;
}
