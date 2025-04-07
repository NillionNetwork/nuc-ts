/**
 * Encode URL safe base64.
 * @param input data to be encoded.
 */
export function base64UrlEncode(input: string | Uint8Array): string {
  const buffer =
    typeof input === "string"
      ? Buffer.from(input, "utf-8")
      : Buffer.from(input);

  return buffer.toString("base64url");
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
