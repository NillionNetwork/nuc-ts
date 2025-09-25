import { bytesToHex } from "@noble/hashes/utils.js";
import { base64url } from "@scure/base";

export function textToHex(text: string): string {
  return bytesToHex(new TextEncoder().encode(text));
}

export function base64UrlEncode(data: Uint8Array): string {
  return base64url.encode(data).replace(/=+$/, "");
}

function addBase64Padding(input: string): string {
  const padding = (4 - (input.length % 4)) % 4;
  return padding > 0 ? input + "=".repeat(padding) : input;
}

export function base64UrlDecodeToBytes(input: string): Uint8Array {
  const padded = addBase64Padding(input);
  return base64url.decode(padded);
}

export function base64UrlDecode(input: string): string {
  const bytes = base64UrlDecodeToBytes(input);
  return new TextDecoder().decode(bytes);
}
