import { Wallet } from "ethers";
import { describe, expect, it } from "vitest";
import * as did from "#/core/did/did";
import * as ethr from "#/core/did/ethr";
import { type Eip712Signer, Signers } from "#/core/signer";
import { Builder } from "#/nuc/builder";
import { validateSignature } from "#/validator/signatures";

describe("EIP-712 Signing and Validation", () => {
  const domain = {
    name: "NUC",
    version: "1",
    chainId: 1,
  };

  const wallet = Wallet.createRandom();
  const audience = ethr.fromAddress(
    "0x742d35cc6634c0532925A3B844bc9E7095ED4E40",
  );

  const eip712Signer: Eip712Signer = {
    getAddress: async () => wallet.address,
    signTypedData: async (domain, types, value) => {
      return wallet.signTypedData(domain, types, value);
    },
  };

  it("should create an EIP-712 signer with correct header", async () => {
    const signer = Signers.fromEip712(eip712Signer, domain);

    expect(signer.header.typ).toBe("nuc+eip712");
    expect(signer.header.alg).toBe("ES256K");
    expect(signer.header.ver).toBe("1.0.0");
    expect(signer.header.meta).toBeDefined();
    expect(signer.header.meta?.domain).toEqual(domain);
    expect(signer.header.meta?.primaryType).toBe("NucPayload");
  });

  it("should generate did:ethr from wallet address", async () => {
    const signer = Signers.fromEip712(eip712Signer, domain);
    const generatedDid = await signer.getDid();

    expect(generatedDid.method).toBe("ethr");
    expect(generatedDid.method === "ethr" && generatedDid.address).toBe(
      wallet.address,
    );
  });

  it("should build and successfully validate an EIP-712 signed delegation", async () => {
    const signer = Signers.fromEip712(eip712Signer, domain);
    const envelope = await Builder.delegation()
      .audience(audience)
      .subject(audience)
      .command("/test")
      .build(signer);

    expect(() => validateSignature(envelope.nuc)).not.toThrow();
  });

  it("should build and successfully validate an EIP-712 signed invocation", async () => {
    const signer = Signers.fromEip712(eip712Signer, domain);
    const envelope = await Builder.invocation()
      .audience(audience)
      .subject(audience)
      .command("/test/invoke")
      .arguments({ file: "doc.pdf", action: "read" })
      .build(signer);

    expect(() => validateSignature(envelope.nuc)).not.toThrow();
  });

  it("should fail validation with wrong address", async () => {
    const signer = Signers.fromEip712(eip712Signer, domain);
    const envelope = await Builder.delegation()
      .audience(audience)
      .subject(audience)
      .command("/test")
      .build(signer);

    // Tamper with the issuer
    envelope.nuc.payload.iss = ethr.fromAddress(
      "0x0000000000000000000000000000000000000000",
    );

    expect(() => validateSignature(envelope.nuc)).toThrow(
      "EIP-712 signature verification failed",
    );
  });

  it("should fail validation for non-ethr DIDs with EIP-712 header", async () => {
    const signer = Signers.fromEip712(eip712Signer, domain);
    const envelope = await Builder.delegation()
      .audience(audience)
      .subject(audience)
      .command("/test")
      .build(signer);

    // Change issuer to non-ethr DID
    envelope.nuc.payload.iss = did.fromPublicKey(new Uint8Array(33));

    expect(() => validateSignature(envelope.nuc)).toThrow(
      "issuer must be a did:ethr for EIP-712 tokens",
    );
  });
});
