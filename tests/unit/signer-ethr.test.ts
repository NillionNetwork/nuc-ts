import { Wallet } from "ethers";
import { describe, expect, it } from "vitest";
import { ONE_HOUR_MS } from "#/constants";
import { Signer } from "#/core/signer";
import { Builder } from "#/nuc/builder";
import { validateNucSignature } from "#/validator/signatures";
import { createNativeEthrSigner } from "#tests/helpers/signers";

describe("Native Signer (`did:ethr`)", () => {
  it("should build and successfully validate a native signed Nuc from an ethers wallet", async () => {
    const wallet = Wallet.createRandom();
    const audienceSigner = Signer.generate();
    const audience = await audienceSigner.getDid();

    const nativeEthrSigner = createNativeEthrSigner(wallet);

    const envelope = await Builder.delegation()
      .audience(audience)
      .subject(audience)
      .command("/test")
      .expiresIn(ONE_HOUR_MS)
      .sign(nativeEthrSigner);

    expect(() => validateNucSignature(envelope.nuc)).not.toThrow();

    expect(envelope.nuc.payload.iss.method).toBe("ethr");
    expect(envelope.nuc.payload.iss.didString).toContain(wallet.address);
  });
});
