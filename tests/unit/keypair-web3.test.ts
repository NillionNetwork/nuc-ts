import { type HDNodeWallet, type TypedDataDomain, Wallet } from "ethers";
import { beforeEach, describe, expect, it } from "vitest";
import { Keypair } from "#/core/keypair";
import { Builder } from "#/nuc/builder";
import { validateNucSignature } from "#/validator/signatures";

describe("Web3 Keypair", () => {
  let wallet: HDNodeWallet;
  let domain: TypedDataDomain;
  let web3Keypair: Keypair;

  beforeEach(async () => {
    wallet = Wallet.createRandom();
    domain = { name: "NUC", version: "1", chainId: 1 };
    web3Keypair = await Keypair.fromEthersSigner(wallet, domain);
  });

  it("should instantiate from an ethers signer", () => {
    expect(web3Keypair).toBeInstanceOf(Keypair);
  });

  it("should return a did:ethr DID", async () => {
    const did = web3Keypair.toDid(); // No args should default to ethr
    expect(did.method).toBe("ethr");
    if (did.method === "ethr") {
      expect(did.address).toBe(await wallet.getAddress());
    }

    const explicitDid = web3Keypair.toDid("ethr");
    expect(explicitDid.method).toBe("ethr");
  });

  it("should throw when requesting a non-ethr DID", () => {
    expect(() => web3Keypair.toDid("key")).toThrow(
      'Web3-based keypairs only support the "ethr" Did method, but "key" was requested.',
    );
    expect(() => web3Keypair.toDid("nil")).toThrow(
      'Web3-based keypairs only support the "ethr" Did method, but "nil" was requested.',
    );
  });

  it("should throw when trying to access unavailable key material", () => {
    expect(() => web3Keypair.privateKey()).toThrow(
      "privateKey is not available for Web3-based keypairs.",
    );
    expect(() => web3Keypair.privateKeyBytes()).toThrow(
      "privateKeyBytes is not available for Web3-based keypairs.",
    );
    expect(() => web3Keypair.publicKey()).toThrow(
      "publicKey is not available for Web3-based keypairs.",
    );
    expect(() => web3Keypair.publicKeyBytes()).toThrow(
      "publicKeyBytes is not available for Web3-based keypairs.",
    );
    expect(() => web3Keypair.matchesPublicKey("some-key")).toThrow(
      "matchesPublicKey is not available for Web3-based keypairs.",
    );
  });

  it("should throw for direct signing methods", () => {
    expect(() => web3Keypair.sign("some text")).toThrow(
      "sign is not available for Web3-based keypairs.",
    );
    expect(() => web3Keypair.signBytes(new Uint8Array([1, 2, 3]))).toThrow(
      "signBytes is not available for Web3-based keypairs.",
    );
  });

  it("should create an EIP-712 signer", () => {
    const signer = web3Keypair.signer(); // No args should default to ethr signer
    expect(signer).toBeDefined();
    expect(signer.header.typ).toBe("nuc+eip712");

    const explicitSigner = web3Keypair.signer("ethr");
    expect(explicitSigner.header.typ).toBe("nuc+eip712");
  });

  it("should throw when requesting a non-ethr signer", () => {
    expect(() => web3Keypair.signer("key")).toThrow(
      'Web3-based keypairs only support the "ethr" Did method for signers, but "key" was requested.',
    );
    expect(() => web3Keypair.signer("nil")).toThrow(
      'Web3-based keypairs only support the "ethr" Did method for signers, but "nil" was requested.',
    );
  });

  it("should build and validate a Nuc signed with a web3 keypair", async () => {
    const signer = web3Keypair.signer();
    const audience = Keypair.generate().toDid();
    const subject = await signer.getDid();

    const envelope = await Builder.delegation()
      .audience(audience)
      .subject(subject)
      .command("/test")
      .sign(signer);

    expect(envelope.nuc.payload.iss.method).toBe("ethr");
    expect(validateNucSignature(envelope.nuc)).toBeUndefined();
  });
});
