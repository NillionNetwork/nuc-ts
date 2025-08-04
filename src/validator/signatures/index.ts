import { base64UrlDecode } from "#/core/encoding";
import type { Envelope, Nuc } from "#/nuc/envelope";
import { validateEip712Signature } from "./eip712";
import { validateNativeSignature } from "./native";

export const INVALID_SIGNATURES = "invalid signatures";

/**
 * Dispatches signature validation based on the Nuc's header type.
 */
export function validateSignature(nuc: Nuc): void {
  const header = JSON.parse(base64UrlDecode(nuc.rawHeader));
  switch (header.typ) {
    case "nuc+eip712":
      validateEip712Signature(nuc);
      break;
    default:
      validateNativeSignature(nuc);
      break;
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
