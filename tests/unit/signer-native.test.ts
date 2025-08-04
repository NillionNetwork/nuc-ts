import { describe, expect, it } from "vitest";
import { Keypair } from "#/core/keypair";
import { Signers } from "#/core/signer";
import { Builder } from "#/nuc/builder";
import { base64UrlDecode } from "#/core/encoding";
import { validateSignature } from "#/validator/signatures";

describe("Native Signer (`did:key`)", () => {
  it("should build and successfully validate a native signed Nuc", async () => {
    const keypair = Keypair.generate();
    const signer = Signers.fromKeypair(keypair);
    const audience = Keypair.generate().toDid();

    const envelope = await Builder.delegation()
      .audience(audience)
      .subject(audience)
      .command("/test")
      .build(signer);

    expect(() => validateSignature(envelope.nuc)).not.toThrow();

    const header = JSON.parse(base64UrlDecode(envelope.nuc.rawHeader));
    expect(header.typ).toBe("nuc");
    expect(header.ver).toBe("1.0.0");
    expect(envelope.nuc.payload.iss.method).toBe("key");
  });
});