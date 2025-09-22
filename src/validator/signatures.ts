import { hexlify, recoverAddress, TypedDataEncoder } from "ethers";
import type { Did } from "#/core/did/did";
import * as ethr from "#/core/did/ethr";
import * as key from "#/core/did/key";
import * as nil from "#/core/did/nil";
import type { DidEthr } from "#/core/did/types";
import { base64UrlDecode } from "#/core/encoding";
import { toEip712Payload } from "#/core/signer";
import type { Envelope, Nuc } from "#/nuc/envelope";

export const INVALID_SIGNATURES = "invalid signatures";

/**
 * Dispatches signature validation based on the Nuc's header type.
 */
export function validateNucSignature(nuc: Nuc): void {
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
export function validateEnvelopeSignature(envelope: Envelope): void {
  validateNucSignature(envelope.nuc);
  for (const proof of envelope.proofs) {
    validateNucSignature(proof);
  }
}

/**
 * Validates the message's signature against the provided did.
 */
export function validateDidSignature(
  did: Did,
  message: Uint8Array,
  signature: Uint8Array,
): boolean {
  switch (did.method) {
    case "key":
      return key.validateSignature(did, message, signature);
    case "ethr":
      return ethr.validateSignature(did, message, signature);
    case "nil":
      return nil.validateSignature(did, message, signature);
  }
}

export const EIP712_INVALID_SIGNATURE = "EIP-712 signature verification failed";
export const EIP712_INVALID_ISSUER =
  "issuer must be a did:ethr for EIP-712 tokens";

/**
 * Validates an eip712 signed message by recovering the public key from the signature.
 */
export function validateEip712Signature(nuc: Nuc): void {
  const { payload, signature } = nuc;
  if (payload.iss.method !== "ethr") throw new Error(EIP712_INVALID_ISSUER);

  const header = JSON.parse(base64UrlDecode(nuc.rawHeader));
  const { domain, primaryType, types } = header.meta;

  // Use the canonical conversion function
  const valueToHash = toEip712Payload(payload);

  const hash = TypedDataEncoder.hash(
    domain,
    { [primaryType]: types.NucPayload },
    valueToHash,
  );
  const recoveredAddress = recoverAddress(hash, hexlify(signature));

  if (
    recoveredAddress.toLowerCase() !==
    (payload.iss as DidEthr).address.toLowerCase()
  ) {
    throw new Error(EIP712_INVALID_SIGNATURE);
  }
}

export const NATIVE_SIGNATURE_VERIFICATION_FAILED =
  "native signature verification failed";

/**
 * Validates an eip712 signed message by recovering the public key from the signature.
 */
export function validateNativeSignature(nuc: Nuc): void {
  const msg = new TextEncoder().encode(`${nuc.rawHeader}.${nuc.rawPayload}`);
  const parsedDid = nuc.payload.iss;

  if (!validateDidSignature(parsedDid, msg, nuc.signature)) {
    throw new Error(NATIVE_SIGNATURE_VERIFICATION_FAILED);
  }
}
