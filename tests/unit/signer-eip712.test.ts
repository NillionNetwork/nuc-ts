import { ONE_HOUR_MS } from "#/constants";
import * as ethr from "#/core/did/ethr";
import { type Eip712Signer, Signer } from "#/core/signer";
import { Builder } from "#/nuc/builder";
import { Codec } from "#/nuc/codec";
import { Validator } from "#/validator/validator";
import { privateKeyToAccount } from "viem/accounts";
import { describe, expect, it } from "vitest";

describe("EIP-712 Signer (`did:ethr`)", () => {
  const account = privateKeyToAccount("0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a");
  const audience = ethr.fromAddress("0x742d35cc6634c0532925A3B844bc9E7095ED4E40");
  const eip712Signer: Eip712Signer = {
    getAddress: async () => account.address,
    signTypedData: async (params) => account.signTypedData(params),
  };

  it("should build and successfully validate an EIP-712 signed delegation", async () => {
    const signer = Signer.fromWeb3(eip712Signer);
    const envelope = await Builder.delegation()
      .audience(audience)
      .subject(audience)
      .command("/test/delegate")
      .expiresIn(ONE_HOUR_MS)
      .sign(signer);

    const did = await signer.getDid();
    const serialized = Codec.serializeBase64Url(envelope);
    const parsed = await Validator.parse(serialized, {
      rootIssuers: [did.didString],
    });
    expect(parsed).toBeDefined();
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

    const did = await signer.getDid();
    const serialized = Codec.serializeBase64Url(envelope);
    const parsed = await Validator.parse(serialized, {
      rootIssuers: [did.didString],
    });
    expect(parsed).toBeDefined();
  });
});
