import { describe, expect, it } from "vitest";
import { ONE_HOUR_MS } from "#/constants";
import { base64UrlDecode } from "#/core/encoding";
import { Signer } from "#/core/signer";
import { Builder } from "#/nuc/builder";
import { validateNucSignature } from "#/validator/signatures";

describe("Native Signer (`did:key`)", () => {
  it("should build and successfully validate a native signed Nuc", async () => {
    const signer = Signer.generate();
    const audienceSigner = Signer.generate();
    const audience = await audienceSigner.getDid();

    const envelope = await Builder.delegation()
      .audience(audience)
      .subject(audience)
      .command("/test")
      .expiresIn(ONE_HOUR_MS)
      .sign(signer);

    expect(() => validateNucSignature(envelope.nuc)).not.toThrow();

    const header = JSON.parse(base64UrlDecode(envelope.nuc.rawHeader));
    expect(header.typ).toBe("nuc");
    expect(header.ver).toBe("1.0.0");
    expect(envelope.nuc.payload.iss.method).toBe("key");
  });
});
