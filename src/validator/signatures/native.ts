import { Did } from "#/core/did/did";
import type { Nuc } from "#/nuc/envelope";

export const NATIVE_SIGNATURE_VERIFICATION_FAILED =
  "native signature verification failed";

export function validateNativeSignature(nuc: Nuc): void {
  const msg = new TextEncoder().encode(`${nuc.rawHeader}.${nuc.rawPayload}`);
  const parsedDid = nuc.payload.iss;

  if (!Did.validateSignature(parsedDid, msg, nuc.signature)) {
    throw new Error(NATIVE_SIGNATURE_VERIFICATION_FAILED);
  }
}
