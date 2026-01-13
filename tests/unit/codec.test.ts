import { ONE_HOUR_MS } from "#/constants";
import { Signer } from "#/core/signer";
import { Builder } from "#/nuc/builder";
import { Codec } from "#/nuc/codec";
import { Validator } from "#/validator/validator";
import * as fc from "fast-check";
import { describe, expect, it } from "vitest";

describe("Codec and Validator.parse", () => {
  const rootSigner = Signer.generate();
  const userSigner = Signer.generate();

  it("should serialize and then parse+validate any token without data loss", async () => {
    await fc.assert(
      fc.asyncProperty(fc.boolean(), async (isChained) => {
        const userDid = await userSigner.getDid();
        const rootEnvelope = await Builder.delegation()
          .audience(userDid)
          .subject(userDid)
          .command("/test")
          .expiresIn(ONE_HOUR_MS)
          .sign(rootSigner);

        const finalEnvelope = isChained
          ? await Builder.delegationFrom(rootEnvelope)
              .audience(await Signer.generate().getDid())
              .expiresIn(ONE_HOUR_MS / 2)
              .sign(userSigner)
          : rootEnvelope;

        const serialized = Codec.serializeBase64Url(finalEnvelope);
        const rootDid = await rootSigner.getDid();

        // The new safe way to parse
        const parsed = await Validator.parse(serialized, {
          rootIssuers: [rootDid.didString],
        });

        // Compare the serialized forms to ensure they produce the same output
        const reserialized = Codec.serializeBase64Url(parsed);
        expect(reserialized).toBe(serialized);
      }),
    );
  });

  // Keep specific error path tests, now testing _unsafeDecodeBase64Url
  describe("error paths for _unsafeDecodeBase64Url", () => {
    it("should throw for an invalid Nuc structure", () => {
      const invalidToken = "a.b";
      expect(() => Codec._unsafeDecodeBase64Url(invalidToken)).toThrow("invalid Nuc structure");
    });

    it("should throw for an invalid header", () => {
      // Create a header with invalid version format
      const invalidHeader = "eyJhbGciOiJFUzI1NksiLCJ2ZXIiOiJpbnZhbGlkIn0.e30.e30"; // {"alg":"ES256K","ver":"invalid"}
      expect(() => Codec._unsafeDecodeBase64Url(invalidHeader)).toThrow("invalid Nuc header");
    });

    it("should throw for empty tokens in a chain", async () => {
      const userDid = await userSigner.getDid();
      const rootEnvelope = await Builder.delegation()
        .audience(userDid)
        .subject(userDid)
        .command("/test")
        .expiresIn(ONE_HOUR_MS)
        .sign(rootSigner);
      const validSerialized = Codec.serializeBase64Url(rootEnvelope);
      const invalidChain = `${validSerialized}//${validSerialized}`;
      expect(() => Codec._unsafeDecodeBase64Url(invalidChain)).toThrow("empty token");
    });

    it("should throw for an empty input string", () => {
      expect(() => Codec._unsafeDecodeBase64Url("")).toThrow("empty token");
    });
  });
});
