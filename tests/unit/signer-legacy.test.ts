import { describe, expect, it } from "vitest";
import { base64UrlDecode } from "#/core/encoding";
import { Keypair } from "#/core/keypair";
import { Signer } from "#/core/signer";
import { Builder } from "#/nuc/builder";
import { validateNucSignature } from "#/validator/signatures";

describe("Legacy Signer (`did:nil`)", () => {
  it("should build and successfully validate a legacy signed Nuc", async () => {
    const keypair = Keypair.generate();
    const signer = Signer.fromLegacyKeypair(keypair);
    const audience = Keypair.generate().toDid("nil");

    const envelope = await Builder.delegation()
      .audience(audience)
      .subject(audience)
      .command("/test")
      .sign(signer);

    expect(() => validateNucSignature(envelope.nuc)).not.toThrow();

    const header = JSON.parse(base64UrlDecode(envelope.nuc.rawHeader));
    expect(header.typ).toBeUndefined();
    expect(header.ver).toBeUndefined();
    expect(envelope.nuc.payload.iss.method).toBe("nil");
  });
});
