import { beforeAll, describe, expect, it } from "vitest";
import { Keypair } from "#/core/keypair";
import { Signers } from "#/core/signer";
import { Builder } from "#/nuc/builder";
import type { Envelope } from "#/nuc/envelope";
import {
  computeHash,
  validateEnvelopeSignatures,
  validateSignature,
} from "#/nuc/envelope";

describe("Envelope Module", () => {
  const rootKeypair = Keypair.generate();
  const userKeypair = Keypair.generate();

  it("should compute a deterministic hash for a Nuc", async () => {
    const envelope = await Builder.delegation()
      .audience(userKeypair.toDid())
      .subject(userKeypair.toDid())
      .command("/test")
      .policy([["==", ".resource", "test"]])
      .build(Signers.fromKeypair(rootKeypair));
    const nuc = envelope.nuc;

    const hash1 = computeHash(nuc);
    const hash2 = computeHash(nuc);

    expect(hash1).toEqual(hash2);
  });

  describe("validateSignature", () => {
    it("should not throw for a valid signature", async () => {
      const envelope = await Builder.delegation()
        .audience(userKeypair.toDid())
        .subject(userKeypair.toDid())
        .command("/test")
        .policy([["==", ".resource", "test"]])
        .build(Signers.fromKeypair(rootKeypair));

      expect(() => validateSignature(envelope.nuc)).not.toThrow();
    });

    it("should throw if the signature is tampered with", async () => {
      const envelope = await Builder.delegation()
        .audience(userKeypair.toDid())
        .subject(userKeypair.toDid())
        .command("/test")
        .policy([["==", ".resource", "test"]])
        .build(Signers.fromKeypair(rootKeypair));

      // Tamper with the signature
      envelope.nuc.signature[0] ^= 0x01;

      expect(() => validateSignature(envelope.nuc)).toThrow(
        "signature verification failed",
      );
    });
  });

  describe("validateEnvelopeSignatures", () => {
    let rootEnvelope: Envelope;
    let chainedEnvelope: Envelope;

    beforeAll(async () => {
      rootEnvelope = await Builder.delegation()
        .audience(userKeypair.toDid())
        .subject(userKeypair.toDid())
        .command("/test")
        .policy([["==", ".resource", "test"]])
        .build(Signers.fromKeypair(rootKeypair));

      chainedEnvelope = await Builder.delegating(rootEnvelope)
        .audience(Keypair.generate().toDid())
        .build(Signers.fromKeypair(userKeypair));
    });

    it("should not throw for a valid envelope with chained proofs", () => {
      expect(() => validateEnvelopeSignatures(chainedEnvelope)).not.toThrow();
    });

    it("should throw if the main Nuc signature is invalid", () => {
      const tamperedEnvelope = { ...chainedEnvelope };
      tamperedEnvelope.nuc.signature[0] ^= 0x01;
      expect(() => validateEnvelopeSignatures(tamperedEnvelope)).toThrow();
    });

    it("should throw if a proof signature is invalid", () => {
      const tamperedEnvelope = { ...chainedEnvelope };
      tamperedEnvelope.proofs[0].signature[0] ^= 0x01;
      expect(() => validateEnvelopeSignatures(tamperedEnvelope)).toThrow();
    });
  });
});
