import * as fc from "fast-check";
import { describe, expect, it } from "vitest";
import { Keypair } from "#/core/keypair";
import { Builder } from "#/nuc/builder";
import { decodeBase64Url, serializeBase64Url } from "#/nuc/codec";

describe("Codec Module", () => {
  const rootKeypair = Keypair.generate();
  const userKeypair = Keypair.generate();

  // Property-Based Test: Serialization and decoding should be inverses.
  it("should serialize and decode any token without data loss", () => {
    fc.assert(
      fc.property(fc.boolean(), (isChained) => {
        const rootEnvelope = Builder.delegation()
          .audience(userKeypair.toDid())
          .subject(userKeypair.toDid())
          .command("/test")
          .build(rootKeypair);

        const finalEnvelope = isChained
          ? Builder.delegating(rootEnvelope)
              .audience(Keypair.generate().toDid())
              .build(userKeypair)
          : rootEnvelope;

        const serialized = serializeBase64Url(finalEnvelope);
        const decoded = decodeBase64Url(serialized);

        // Compare the serialized forms to ensure they produce the same output
        const reserialized = serializeBase64Url(decoded);
        expect(reserialized).toBe(serialized);
      }),
    );
  });

  // Keep specific error path tests
  describe("error paths", () => {
    it("should throw for an invalid Nuc structure", () => {
      const invalidToken = "a.b";
      expect(() => decodeBase64Url(invalidToken)).toThrow(
        "invalid Nuc structure",
      );
    });

    it("should throw for an invalid header", () => {
      const invalidHeader = "eyJhbGciOiJub25lIn0.e30.e30";
      expect(() => decodeBase64Url(invalidHeader)).toThrow(
        "invalid Nuc header",
      );
    });

    it("should throw for empty tokens in a chain", () => {
      const rootEnvelope = Builder.delegation()
        .audience(userKeypair.toDid())
        .subject(userKeypair.toDid())
        .command("/test")
        .build(rootKeypair);
      const validSerialized = serializeBase64Url(rootEnvelope);
      const invalidChain = `${validSerialized}//${validSerialized}`;
      expect(() => decodeBase64Url(invalidChain)).toThrow("empty token");
    });

    it("should throw for an empty input string", () => {
      expect(() => decodeBase64Url("")).toThrow("empty token");
    });
  });
});
