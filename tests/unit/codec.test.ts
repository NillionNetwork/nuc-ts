import * as fc from "fast-check";
import { describe, expect, it } from "vitest";
import { Signer } from "#/core/signer";
import { Builder } from "#/nuc/builder";
import { Codec } from "#/nuc/codec";

describe("Codec Module", () => {
  const rootSigner = Signer.generate();
  const userSigner = Signer.generate();

  // Property-Based Test: Serialization and decoding should be inverses.
  it("should serialize and decode any token without data loss", async () => {
    await fc.assert(
      fc.asyncProperty(fc.boolean(), async (isChained) => {
        const userDid = await userSigner.getDid();
        const rootEnvelope = await Builder.delegation()
          .audience(userDid)
          .subject(userDid)
          .command("/test")
          .sign(rootSigner);

        const finalEnvelope = isChained
          ? await Builder.delegationFrom(rootEnvelope)
              .audience(await Signer.generate().getDid())
              .sign(userSigner)
          : rootEnvelope;

        const serialized = Codec.serializeBase64Url(finalEnvelope);
        const decoded = Codec.decodeBase64Url(serialized);

        // Compare the serialized forms to ensure they produce the same output
        const reserialized = Codec.serializeBase64Url(decoded);
        expect(reserialized).toBe(serialized);
      }),
    );
  });

  // Keep specific error path tests
  describe("error paths", () => {
    it("should throw for an invalid Nuc structure", () => {
      const invalidToken = "a.b";
      expect(() => Codec.decodeBase64Url(invalidToken)).toThrow(
        "invalid Nuc structure",
      );
    });

    it("should throw for an invalid header", () => {
      // Create a header with invalid version format
      const invalidHeader =
        "eyJhbGciOiJFUzI1NksiLCJ2ZXIiOiJpbnZhbGlkIn0.e30.e30"; // {"alg":"ES256K","ver":"invalid"}
      expect(() => Codec.decodeBase64Url(invalidHeader)).toThrow(
        "invalid Nuc header",
      );
    });

    it("should throw for empty tokens in a chain", async () => {
      const userDid = await userSigner.getDid();
      const rootEnvelope = await Builder.delegation()
        .audience(userDid)
        .subject(userDid)
        .command("/test")
        .sign(rootSigner);
      const validSerialized = Codec.serializeBase64Url(rootEnvelope);
      const invalidChain = `${validSerialized}//${validSerialized}`;
      expect(() => Codec.decodeBase64Url(invalidChain)).toThrow("empty token");
    });

    it("should throw for an empty input string", () => {
      expect(() => Codec.decodeBase64Url("")).toThrow("empty token");
    });
  });
});
