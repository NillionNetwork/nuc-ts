import { sha256 } from "@noble/hashes/sha256";
import { toBytes } from "@noble/hashes/utils";
import { z } from "zod";
import * as did from "#/core/did/did";
import { base64UrlEncode } from "#/core/encoding";
import { PayloadSchema } from "#/nuc/payload";

const SIGNATURE_VERIFICATION_FAILED = "signature verification failed";

export const NucSchema = z.object({
  rawHeader: z.string(),
  rawPayload: z.string(),
  signature: z.instanceof(Uint8Array),
  payload: PayloadSchema,
});
export type Nuc = z.infer<typeof NucSchema>;

export const EnvelopeSchema = z.object({
  nuc: NucSchema,
  proofs: z.array(NucSchema),
});
export type Envelope = z.infer<typeof EnvelopeSchema>;

/**
 * Validate the signature of a decoded NUC.
 */
export function validateSignature(nuc: Nuc): void {
  const msg = toBytes(`${nuc.rawHeader}.${nuc.rawPayload}`);
  const parsedDid = nuc.payload.iss;

  if (!did.validateSignature(parsedDid, msg, nuc.signature)) {
    throw new Error(SIGNATURE_VERIFICATION_FAILED);
  }
}

/**
 * Validate all signatures in an envelope.
 */
export function validateEnvelopeSignatures(envelope: Envelope): void {
  validateSignature(envelope.nuc);
  for (const proof of envelope.proofs) {
    validateSignature(proof);
  }
}

/**
 * Compute the hash for a decoded Nuc.
 */
export function computeHash(nuc: Nuc): Uint8Array {
  const signature = base64UrlEncode(nuc.signature);
  const serialized = `${nuc.rawHeader}.${nuc.rawPayload}.${signature}`;
  return sha256(serialized);
}
