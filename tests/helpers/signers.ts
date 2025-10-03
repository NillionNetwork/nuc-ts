import { hexToBytes } from "@noble/hashes/utils.js";
import type { HDNodeWallet } from "ethers";
import * as ethr from "#/core/did/ethr";
import type { Signer } from "#/core/signer";
import { NucHeaders } from "#/nuc/header";

/**
 * Creates a native `did:ethr` signer from an ethers Wallet instance.
 * This is useful for tests that require a `did:ethr` identity but
 * do not need the full EIP-712 typed data signing flow.
 */
export function createNativeEthrSigner(wallet: HDNodeWallet): Signer {
  return {
    header: NucHeaders.v1,
    getDid: async () => ethr.fromAddress(await wallet.getAddress()),
    sign: async (data: Uint8Array): Promise<Uint8Array> => {
      const signatureHex = await wallet.signMessage(data);
      // Remove 0x prefix if present
      const cleanHex = signatureHex.startsWith("0x")
        ? signatureHex.slice(2)
        : signatureHex;
      return hexToBytes(cleanHex);
    },
  };
}
