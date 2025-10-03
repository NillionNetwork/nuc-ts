import { describe, expect, it } from "vitest";
import { Did } from "#/core/did/did";
import type { DidKey, DidNil } from "#/core/did/types";
import { Signer } from "#/core/signer";

describe("Dids", () => {
  // Generate a single signer to create both nil and key DIDs from
  const testSigner = Signer.generate();
  const privateKey = new Uint8Array(32);
  crypto.getRandomValues(privateKey);

  it("parses and stringifies did:nil correctly", async () => {
    const nilSigner = Signer.fromPrivateKey(privateKey, "nil");
    const nilDid = (await nilSigner.getDid()) as DidNil;
    const parsed = Did.parse(nilDid.didString) as DidNil;
    expect(parsed.didString).toEqual(nilDid.didString);
    expect(parsed.method).toEqual(nilDid.method);
    expect(parsed.publicKeyBytes).toEqual(nilDid.publicKeyBytes);
    const stringified = Did.serialize(parsed);
    expect(stringified).toEqual(nilDid.didString);
  });

  it("parses and stringifies did:key correctly", async () => {
    const keyDid = (await testSigner.getDid()) as DidKey;
    expect(keyDid.didString.startsWith("did:key:z")).toBe(true);
    const parsed = Did.parse(keyDid.didString) as DidKey;
    expect(parsed.didString).toEqual(keyDid.didString);
    expect(parsed.method).toEqual(keyDid.method);
    expect(parsed.publicKeyBytes).toEqual(keyDid.publicKeyBytes);
    if (parsed.method === "key" && keyDid.method === "key") {
      expect(parsed.multicodec).toEqual(keyDid.multicodec);
    }
    const stringified = Did.serialize(parsed);
    expect(stringified).toEqual(keyDid.didString);
  });

  it("throws on unsupported method", () => {
    expect(() => Did.parse("did:unsupported:123")).toThrow(
      "Unsupported Did method",
    );
  });

  it("correctly compares Dids for equality", async () => {
    const keySigner = Signer.fromPrivateKey(privateKey, "key");
    const nilSigner = Signer.fromPrivateKey(privateKey, "nil");

    const keyDid = await keySigner.getDid();
    const nilDid = await nilSigner.getDid();

    const parsedKey1 = Did.parse(keyDid.didString);
    const parsedKey2 = Did.parse(keyDid.didString);
    const parsedNil = Did.parse(nilDid.didString);

    expect(Did.areEqual(parsedKey1, parsedKey2)).toBe(true);
    // key and nil are comparable
    expect(Did.areEqual(parsedKey1, parsedNil)).toBe(true);

    const other = await Signer.generate().getDid();
    expect(Did.areEqual(other, parsedKey1)).toBe(false);
  });

  describe("DidSchema", () => {
    it("should parse a valid did:key", async () => {
      const didString = Did.serialize(await Signer.generate().getDid());
      expect(Did.Schema.safeParse(didString).success).toBe(true);
    });

    it("should fail to parse an invalid Did", () => {
      const didString = "invalid-did";
      expect(Did.Schema.safeParse(didString).success).toBe(false);
    });
  });
});
