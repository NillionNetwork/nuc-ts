import * as ethr from "#/core/did/ethr";
import type { Signer } from "#/core/signer";
import { NucHeaders } from "#/nuc/header";
import { hexToBytes } from "@noble/hashes/utils.js";
import type { PrivateKeyAccount } from "viem/accounts";

/**
 * Creates a native `did:ethr` signer from a viem PrivateKeyAccount instance.
 * This is useful for tests that require a `did:ethr` identity but
 * do not need the full EIP-712 typed data signing flow.
 */
export function createNativeEthrSigner(account: PrivateKeyAccount): Signer {
  return {
    header: NucHeaders.v1,
    getDid: async () => ethr.fromAddress(account.address),
    sign: async (data: Uint8Array): Promise<Uint8Array> => {
      const signatureHex = await account.signMessage({
        message: { raw: data },
      });
      // Remove 0x prefix if present
      const cleanHex = signatureHex.startsWith("0x") ? signatureHex.slice(2) : signatureHex;
      return hexToBytes(cleanHex);
    },
  };
}
