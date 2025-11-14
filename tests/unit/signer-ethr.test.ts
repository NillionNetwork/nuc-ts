import { privateKeyToAccount } from "viem/accounts";
import { describe, expect, it } from "vitest";
import { ONE_HOUR_MS } from "#/constants";
import { Signer } from "#/core/signer";
import { Builder } from "#/nuc/builder";
import { Codec } from "#/nuc/codec";
import { Validator } from "#/validator/validator";
import { createNativeEthrSigner } from "#tests/helpers/signers";

async function assertValidParse(
  envelope: Awaited<
    ReturnType<(typeof Builder.delegation)["prototype"]["sign"]>
  >,
  rootDidString: string,
) {
  const serialized = Codec.serializeBase64Url(envelope);
  const parsed = await Validator.parse(serialized, {
    rootIssuers: [rootDidString],
  });
  expect(parsed).toBeDefined();
}

describe("Native Signer (`did:ethr`)", () => {
  it("should build and successfully validate a native signed Nuc from a viem account", async () => {
    const account = privateKeyToAccount(
      "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
    );
    const audienceSigner = Signer.generate();
    const audience = await audienceSigner.getDid();

    const nativeEthrSigner = createNativeEthrSigner(account);

    const envelope = await Builder.delegation()
      .audience(audience)
      .subject(audience)
      .command("/test")
      .expiresIn(ONE_HOUR_MS)
      .sign(nativeEthrSigner);

    const did = await nativeEthrSigner.getDid();
    await assertValidParse(envelope, did.didString);

    expect(envelope.nuc.payload.iss.method).toBe("ethr");
    expect(envelope.nuc.payload.iss.didString).toContain(account.address);
  });
});
