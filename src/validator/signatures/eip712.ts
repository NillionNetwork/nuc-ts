import { hexlify, recoverAddress, TypedDataEncoder } from "ethers";
import * as did from "#/core/did/did";
import type { DidEthr } from "#/core/did/types";
import { base64UrlDecode } from "#/core/encoding";
import type { Nuc } from "#/nuc/envelope";
import { isDelegationPayload } from "#/nuc/payload";

export const EIP712_INVALID_SIGNATURE = "EIP-712 signature verification failed";
export const EIP712_INVALID_ISSUER =
  "issuer must be a did:ethr for EIP-712 tokens";

export function validateEip712Signature(nuc: Nuc): void {
  const { payload, signature } = nuc;
  if (payload.iss.method !== "ethr") throw new Error(EIP712_INVALID_ISSUER);

  const header = JSON.parse(base64UrlDecode(nuc.rawHeader));
  const { domain, primaryType, types } = header.meta;

  const valueToHash = {
    iss: did.serialize(payload.iss),
    sub: did.serialize(payload.sub),
    aud: did.serialize(payload.aud),
    cmd: payload.cmd,
    pol: JSON.stringify(isDelegationPayload(payload) ? payload.pol : []),
    nonce: payload.nonce,
    nbf: payload.nbf || 0,
    exp: payload.exp || 0,
    prf: payload.prf || [],
  };

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
