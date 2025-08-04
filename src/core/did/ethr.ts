import type { DidEthr } from "#/core/did/types";

export function parse(_didString: string): DidEthr {
  throw new Error("did:ethr parsing is not yet implemented.");
}

export function serialize(_did: DidEthr): string {
  throw new Error("did:ethr serialize is not yet implemented.");
}

export function validateSignature(
  _did: DidEthr,
  _message: Uint8Array,
  _signature: Uint8Array,
): boolean {
  throw new Error("did:ethr signature validation is not yet implemented.");
}
