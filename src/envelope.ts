import { secp256k1 } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha256";
import { toBytes } from "@noble/hashes/utils";
import { z } from "zod";
import { type NucToken, NucTokenSchema } from "#/token";
import {
  base64UrlDecode,
  base64UrlDecodeToBytes,
  base64UrlEncode,
} from "#/utils";

const INVALID_JWT_STRUCTURE = "invalid JWT structure";
const INVALID_JWT_HEADER = "invalid JWT header";
const SIGNATURE_VERIFICATION_FAILED = "signature verification failed";

export const NucTokenEnvelopeSchema = z
  .string()
  .transform((data) => data.split("/"))
  .refine((tokens) => tokens.every(Boolean), "empty token")
  .transform((tokens) =>
    tokens.map((token) => DecodedNucTokenSchema.parse(token)),
  )
  .refine((tokens) => tokens && tokens.length > 0)
  .transform((tokens) => new NucTokenEnvelope(tokens[0], tokens.slice(1)));

/**
 * A NUC token envelope, containing a parsed token along with all its proofs.
 */
export class NucTokenEnvelope {
  constructor(
    public readonly token: DecodedNucToken,
    public readonly proofs: Array<DecodedNucToken>,
  ) {}

  /**
   * Validate the signature in this envelope.
   *
   * This will raise an exception is the token or any of its proofs is not signed by its issuer.
   */
  validateSignatures() {
    for (const token of [this.token, ...this.proofs]) {
      token.validateSignature();
    }
  }

  /**
   * Serialize this envelope as a JWT-like string.
   */
  serialize(): string {
    return `${[this.token, ...this.proofs].map((proof) => proof.serialize()).join("/")}`;
  }
}

export const HeaderSchema = z.object({
  alg: z.literal("ES256K"),
});

export const DecodedNucTokenSchema = z
  .string()
  .transform((data) => data.split("."))
  .refine((tokens) => tokens && tokens.length === 3, INVALID_JWT_STRUCTURE)
  .refine(
    ([rawHeader, _]) =>
      HeaderSchema.parse(JSON.parse(base64UrlDecode(rawHeader))),
    INVALID_JWT_HEADER,
  )
  .transform(([rawHeader, rawPayload, rawSignature]) => {
    const token = NucTokenSchema.parse(JSON.parse(base64UrlDecode(rawPayload)));
    const signature = base64UrlDecodeToBytes(rawSignature);
    return new DecodedNucToken(rawHeader, rawPayload, signature, token);
  });

/**
 * A decoded NUC token.
 */
export class DecodedNucToken {
  constructor(
    public readonly rawHeader: string,
    public readonly rawPayload: string,
    public readonly signature: Uint8Array,
    public readonly token: NucToken,
  ) {}

  /**
   * Validate the signature in this token.
   */
  validateSignature() {
    const msg = toBytes(`${this.rawHeader}.${this.rawPayload}`);
    if (
      !secp256k1.verify(this.signature, msg, this.token.issuer.publicKey, {
        prehash: true,
      })
    ) {
      throw new Error(SIGNATURE_VERIFICATION_FAILED);
    }
  }

  /**
   * Compute the hash for this token.
   */
  computeHash(): Uint8Array {
    return sha256(this.serialize());
  }

  /**
   * Serialize this token as a JWT.
   */
  serialize(): string {
    return `${this.rawHeader}.${this.rawPayload}.${base64UrlEncode(this.signature)}`;
  }
}
