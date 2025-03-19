import { createHash } from "node:crypto";
import { secp256k1 } from "@noble/curves/secp256k1";
import { z } from "zod";
import { type NucToken, NucTokenSchema } from "#/token";
import {
  base64UrlDecode,
  base64UrlDecodeToBytes,
  base64UrlEncode,
} from "#/utils";

export const NucTokenEnvelopeSchema = z
  .string()
  .transform((data) => data.split("/"))
  .refine((tokens) => tokens.every(Boolean), "empty token")
  .transform((tokens) =>
    tokens.map((token) => DecodedNucTokenSchema.parse(token)),
  )
  .refine((tokens) => tokens && tokens.length > 0)
  .transform((tokens) => new NucTokenEnvelope(tokens[0], tokens.slice(1)));

export class NucTokenEnvelope {
  constructor(
    public readonly token: DecodedNucToken,
    public readonly proofs: Array<DecodedNucToken>,
  ) {}

  validateSignatures() {
    this.token.validateSignature();
    for (const proof of this.proofs) {
      proof.validateSignature();
    }
  }
}

export const HeaderSchema = z.object({
  alg: z.literal("ES256K"),
});

export const DecodedNucTokenSchema = z
  .string()
  .transform((data) => data.split("."))
  .refine((tokens) => tokens && tokens.length === 3, "invalid JWT structure")
  .refine(
    ([rawHeader, _]) =>
      HeaderSchema.parse(JSON.parse(base64UrlDecode(rawHeader))),
    "invalid JWT header",
  )
  .transform(([rawHeader, rawPayload, rawSignature]) => {
    const token = NucTokenSchema.parse(JSON.parse(base64UrlDecode(rawPayload)));
    const signature = base64UrlDecodeToBytes(rawSignature);
    return new DecodedNucToken(rawHeader, rawPayload, signature, token);
  });

export class DecodedNucToken {
  constructor(
    public readonly rawHeader: string,
    public readonly rawPayload: string,
    public readonly signature: Uint8Array,
    public readonly token: NucToken,
  ) {}

  validateSignature() {
    const signature = this.signature;
    const msg = new Uint8Array(
      Buffer.from(`${this.rawHeader}.${this.rawPayload}`),
    );
    const publicKey = new Uint8Array(Buffer.from(this.token.issuer.publicKey));
    if (!secp256k1.verify(signature, msg, publicKey, { prehash: true })) {
      throw new Error("signature verification failed");
    }
  }

  computeHash(): Uint8Array {
    return Uint8Array.from(
      createHash("sha256").update(this.toString()).digest(),
    );
  }

  toString(): string {
    return `${this.rawHeader}.${this.rawPayload}.${base64UrlEncode(this.signature)}`;
  }
}
