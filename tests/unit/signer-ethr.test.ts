import { hexToBytes } from "@noble/hashes/utils.js";
import { Wallet } from "ethers";
import { describe, expect, it } from "vitest";
import * as ethr from "#/core/did/ethr";
import type { Signer as SignerType } from "#/core/signer";
import { Signer } from "#/core/signer";
import { Builder } from "#/nuc/builder";
import { NucHeaders } from "#/nuc/header";
import { validateNucSignature } from "#/validator/signatures";

describe("Native Signer (`did:ethr`)", () => {
  it("should build and successfully validate a native signed Nuc from an ethers wallet", async () => {
    const wallet = Wallet.createRandom();
    const audienceSigner = Signer.generate();
    const audience = await audienceSigner.getDid();

    const nativeEthrSigner: SignerType = {
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

    const envelope = await Builder.delegation()
      .audience(audience)
      .subject(audience)
      .command("/test")
      .sign(nativeEthrSigner);

    expect(() => validateNucSignature(envelope.nuc)).not.toThrow();

    expect(envelope.nuc.payload.iss.method).toBe("ethr");
    expect(envelope.nuc.payload.iss.didString).toContain(wallet.address);
  });
});
