import { Wallet } from "ethers";
import { describe, expect, it } from "vitest";
import { ONE_HOUR_MS } from "#/constants";
import * as ethr from "#/core/did/ethr";
import { type Eip712Signer, Signer } from "#/core/signer";
import { Builder } from "#/nuc/builder";
import { validateNucSignature } from "#/validator/signatures";

describe("EIP-712 Signer (`did:ethr`)", () => {
  const wallet = Wallet.createRandom();
  const audience = ethr.fromAddress(
    "0x742d35cc6634c0532925A3B844bc9E7095ED4E40",
  );
  const eip712Signer: Eip712Signer = {
    getAddress: async () => wallet.address,
    signTypedData: async (domain, types, value) =>
      wallet.signTypedData(domain, types, value),
  };

  it("should build and successfully validate an EIP-712 signed delegation", async () => {
    const signer = Signer.fromWeb3(eip712Signer);
    const envelope = await Builder.delegation()
      .audience(audience)
      .subject(audience)
      .command("/test/delegate")
      .expiresIn(ONE_HOUR_MS)
      .sign(signer);

    expect(() => validateNucSignature(envelope.nuc)).not.toThrow();
  });

  it("should build and successfully validate an EIP-712 signed invocation", async () => {
    const signer = Signer.fromWeb3(eip712Signer);
    const envelope = await Builder.invocation()
      .audience(audience)
      .subject(audience)
      .command("/test/invoke")
      .arguments({ test: true })
      .expiresIn(ONE_HOUR_MS)
      .sign(signer);

    expect(() => validateNucSignature(envelope.nuc)).not.toThrow();
  });
});
