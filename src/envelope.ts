import { secp256k1 } from "@noble/curves/secp256k1";
import { z } from "zod";
import type { NucToken } from "#/token";
import { NucTokenSchema } from "#/types";
import { base64UrlDecode, base64UrlDecodeToBytes } from "#/utils";

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
  private readonly _token: DecodedNucToken;
  private readonly _proofs: Array<DecodedNucToken>;

  constructor(token: DecodedNucToken, proofs: Array<DecodedNucToken>) {
    this._token = token;
    this._proofs = proofs;
  }

  validateSignatures() {
    this._token.validateSignature();
    for (const proof of this._proofs) {
      proof.validateSignature();
    }
  }

  get token(): NucToken {
    return this._token.token;
  }

  get proofs(): Array<NucToken> {
    return this._proofs.map((proof) => proof.token);
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
  public readonly rawHeader: string;
  public readonly rawPayload: string;
  public readonly signature: Uint8Array;
  public token: NucToken;

  constructor(
    rawHeader: string,
    rawPayload: string,
    signature: Uint8Array,
    token: NucToken,
  ) {
    this.rawHeader = rawHeader;
    this.rawPayload = rawPayload;
    this.signature = signature;
    this.token = token;
  }

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
}
