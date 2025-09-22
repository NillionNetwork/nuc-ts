import { getAddress } from "ethers";
import type { DidEthr } from "#/core/did/types";

/**
 * Creates a did:ethr DID from an Ethereum address.
 * @param address The Ethereum address (will be checksummed)
 * @returns A did:ethr DID
 * @example
 * ```typescript
 * const did = fromAddress("0x742d35Cc6634C0532925a3b844Bc9e7095Ed4e40");
 * // Returns: { method: "ethr", address: "0x742d35Cc6634C0532925a3b844Bc9e7095Ed4e40" }
 * ```
 */
export function fromAddress(address: string): DidEthr {
  const checksumAddress = getAddress(address);
  const didString = `did:ethr:${checksumAddress}`;
  return {
    method: "ethr",
    address: checksumAddress,
    didString,
    toJSON: () => didString,
  };
}

/**
 * Serializes a did:ethr DID to its string representation.
 * @param did The did:ethr DID to serialize
 * @returns The DID string
 * @example
 * ```typescript
 * const didString = serialize({ method: "ethr", address: "0x742d35..." });
 * // Returns: "did:ethr:0x742d35..."
 * ```
 */
export function serialize(did: DidEthr): string {
  return `did:ethr:${did.address}`;
}

/**
 * Parses a did:ethr string into a DidEthr object.
 * @param didString The DID string to parse
 * @returns The parsed DidEthr object
 * @throws If the DID is not a valid did:ethr
 * @example
 * ```typescript
 * const did = parse("did:ethr:0x742d35Cc6634C0532925a3b844Bc9e7095Ed4e40");
 * // Returns: { method: "ethr", address: "0x742d35Cc6634C0532925a3b844Bc9e7095Ed4e40" }
 * ```
 */
export function parse(didString: string): DidEthr {
  const parts = didString.split(":");
  if (parts.length !== 3 || parts[0] !== "did" || parts[1] !== "ethr") {
    throw new Error("Invalid did:ethr format");
  }
  const checksumAddress = getAddress(parts[2]);
  return {
    method: "ethr",
    address: checksumAddress,
    didString,
    toJSON: () => didString,
  };
}

/**
 * Validates a did:ethr signature.
 *
 * @param _did The did:ethr DID
 * @param _message The message that was signed
 * @param _signature The signature to validate
 * @returns True if the message was signed by the provided did.
 */
export function validateSignature(
  _did: DidEthr,
  _message: Uint8Array,
  _signature: Uint8Array,
): boolean {
  throw new Error(
    "did:ethr signature validation happens in the EIP-712 validator",
  );
}
