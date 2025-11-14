import { describe, expect, it } from "vitest";
import { ONE_HOUR_MS } from "#/constants";
import { base64UrlDecode } from "#/core/encoding";
import { Signer } from "#/core/signer";
import { Builder } from "#/nuc/builder";
import { Codec } from "#/nuc/codec";
import { Validator } from "#/validator/validator";

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

describe("Legacy Signer (`did:nil`)", () => {
  it("should build and successfully validate a legacy signed Nuc", async () => {
    const signer = Signer.generate("nil");
    const audienceSigner = Signer.generate("nil");
    const audience = await audienceSigner.getDid();

    const envelope = await Builder.delegation()
      .audience(audience)
      .subject(audience)
      .command("/test")
      .expiresIn(ONE_HOUR_MS)
      .sign(signer);

    const did = await signer.getDid();
    await assertValidParse(envelope, did.didString);

    const header = JSON.parse(base64UrlDecode(envelope.nuc.rawHeader));
    expect(header.typ).toBeUndefined();
    expect(header.ver).toBeUndefined();
    expect(envelope.nuc.payload.iss.method).toBe("nil");
  });
});
