import { base64UrlEncode } from "#/core/encoding";
import { Payload } from "#/nuc/payload";
import { sha256 } from "@noble/hashes/sha2.js";
import { z } from "zod";

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
   * Compute a decoded Nuc's sha256 hash.
   */
  export function computeHash(nuc: Nuc): Uint8Array {
    const signature = base64UrlEncode(nuc.signature);
    const serialized = `${nuc.rawHeader}.${nuc.rawPayload}.${signature}`;
    const asBytes = new TextEncoder().encode(serialized);
    return sha256(asBytes);
  }
}
