import { sha256 } from "@noble/hashes/sha2";
import { z } from "zod";
import { base64UrlEncode } from "#/core/encoding";
import { Payload } from "#/nuc/payload";

const NucSchema = z.object({
  rawHeader: z.string(),
  rawPayload: z.string(),
  signature: z.instanceof(Uint8Array),
  payload: Payload.Schema,
});
export type Nuc = z.infer<typeof NucSchema>;

export type Envelope = z.infer<typeof EnvelopeSchema>;
const EnvelopeSchema = z.object({
  nuc: NucSchema,
  proofs: z.array(NucSchema),
});

export namespace Envelope {
  export const Schema = EnvelopeSchema;

  /**
   * Compute the hash for a decoded Nuc.
   */
  export function computeHash(nuc: Nuc): Uint8Array {
    const signature = base64UrlEncode(nuc.signature);
    const serialized = `${nuc.rawHeader}.${nuc.rawPayload}.${signature}`;
    return sha256(serialized);
  }
}
