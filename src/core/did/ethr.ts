import { bytesToHex } from "@noble/hashes/utils.js";
import { getAddress } from "viem";
import { hashMessage, recoverAddress } from "viem/utils";
import type { DidEthr } from "#/core/did/types";

/**
 * Creates a did:ethr Did from an Ethereum address.
 * @param address The Ethereum address (will be checksummed)
 * @returns A did:ethr Did
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
 * Serializes a did:ethr Did to its string representation.
 * @param did The did:ethr Did to serialize
 * @returns The Did string
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
 * @param didString The Did string to parse
 * @returns The parsed DidEthr object
 * @throws If the Did is not a valid did:ethr
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
 * @param did The did:ethr Did
 * @param message The message that was signed
 * @param signature The signature to validate
 * @returns True if the message was signed by the provided did.
 */
export async function validateSignature(
  did: DidEthr,
  message: Uint8Array,
  signature: Uint8Array,
): Promise<boolean> {
  const messageHash = hashMessage({ raw: message });
  const recoveredAddress = await recoverAddress({
    hash: messageHash,
    signature: bytesToHex(signature) as `0x${string}`,
  });
  return getAddress(recoveredAddress) === did.address;
}
