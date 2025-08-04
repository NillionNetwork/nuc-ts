import { sha256 } from "@noble/hashes/sha256";
import { z } from "zod";
import { base64UrlEncode } from "#/core/encoding";
import { PayloadSchema } from "#/nuc/payload";

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
 * Compute the hash for a decoded Nuc.
 */
export function computeHash(nuc: Nuc): Uint8Array {
  const signature = base64UrlEncode(nuc.signature);
  const serialized = `${nuc.rawHeader}.${nuc.rawPayload}.${signature}`;
  return sha256(serialized);
}
