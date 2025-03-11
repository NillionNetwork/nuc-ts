export function base64UrlEncode(data: string | Uint8Array): string {
  const base64 = Buffer.from(data).toString("base64");
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function base64UrlDecode(base64Url: string | Uint8Array): string {
  return Buffer.from(base64UrlToBase64(base64Url), "base64").toString();
}

export function base64UrlDecodeToBytes(base64Url: string): Uint8Array {
  return new Uint8Array(Buffer.from(base64UrlToBase64(base64Url), "base64"));
}

function base64UrlToBase64(data: string | Uint8Array): string {
  const base64url =
    typeof data === "string" ? data : Buffer.from(data).toString();
  let base64 = base64url.replace(/-/g, "+").replace(/_/g, "/");
  while (base64.length % 4 !== 0) {
    base64 += "=";
  }
  return base64;
}
