import { describe, expect, it } from "vitest";
import { base64UrlDecode } from "#/core/encoding";
import { Keypair } from "#/core/keypair";
import { Signer } from "#/core/signer";
import { Builder } from "#/nuc/builder";
import { validateNucSignature } from "#/validator/signatures";

describe("Native Signer (`did:key`)", () => {
  it("should build and successfully validate a native signed Nuc", async () => {
    const keypair = Keypair.generate();
    const signer = Signer.fromKeypair(keypair);
    const audience = Keypair.generate().toDid();

    const envelope = await Builder.delegation()
      .audience(audience)
      .subject(audience)
      .command("/test")
      .build(signer);

    expect(() => validateNucSignature(envelope.nuc)).not.toThrow();

    const header = JSON.parse(base64UrlDecode(envelope.nuc.rawHeader));
    expect(header.typ).toBe("nuc");
    expect(header.ver).toBe("1.0.0");
    expect(envelope.nuc.payload.iss.method).toBe("key");
  });
});
