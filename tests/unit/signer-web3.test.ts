import { type HDNodeWallet, type TypedDataDomain, Wallet } from "ethers";
import { beforeEach, describe, expect, it } from "vitest";
import type { Signer as NucSigner } from "#/core/signer";
import { Signer } from "#/core/signer";
import { Builder } from "#/nuc/builder";
import { validateNucSignature } from "#/validator/signatures";

describe("Web3 Signer (EIP-712)", () => {
  let wallet: HDNodeWallet;
  let domain: TypedDataDomain;
  let web3Signer: NucSigner;

  beforeEach(async () => {
    wallet = Wallet.createRandom();
    domain = { name: "NUC", version: "1", chainId: 1 };
    web3Signer = Signer.fromWeb3(wallet, domain);
  });

  it("should instantiate from an ethers signer using Signer.fromWeb3", () => {
    expect(web3Signer).toBeDefined();
    expect(web3Signer.header).toBeDefined();
    expect(web3Signer.getDid).toBeDefined();
    expect(web3Signer.sign).toBeDefined();
  });

  it("should return a did:ethr DID", async () => {
    const did = await web3Signer.getDid();
    expect(did.method).toBe("ethr");
    if (did.method === "ethr") {
      expect(did.address).toBe(await wallet.getAddress());
    }
  });

  it("should have an EIP-712 header", () => {
    expect(web3Signer.header.typ).toBe("nuc+eip712");
    expect(web3Signer.header.alg).toBe("ES256K");
    expect(web3Signer.header.ver).toBe("1.0.0");
  });

  it("should build and validate a Nuc signed with EIP-712", async () => {
    const audienceSigner = Signer.generate();
    const audience = await audienceSigner.getDid();
    const subject = await web3Signer.getDid();

    const envelope = await Builder.delegation()
      .audience(audience)
      .subject(subject)
      .command("/test")
      .sign(web3Signer);

    expect(envelope.nuc.payload.iss.method).toBe("ethr");
    expect(validateNucSignature(envelope.nuc)).toBeUndefined();
  });

  it("should sign and verify a complex delegation chain", async () => {
    const userSigner = Signer.generate();
    const userDid = await userSigner.getDid();
    const serviceDid = await Signer.generate().getDid();

    // Root delegation from web3 signer to user
    const rootDelegation = await Builder.delegation()
      .audience(userDid)
      .subject(userDid)
      .command("/test/data")
      .sign(web3Signer);

    // User creates an invocation
    const invocation = await Builder.invocationFrom(rootDelegation)
      .audience(serviceDid)
      .arguments({ action: "read" })
      .sign(userSigner);

    expect(invocation.proofs).toHaveLength(1);
    expect(invocation.nuc.payload.iss.method).toBe("key");
    expect(invocation.proofs[0].payload.iss.method).toBe("ethr");
    expect(validateNucSignature(invocation.nuc)).toBeUndefined();
    expect(validateNucSignature(invocation.proofs[0])).toBeUndefined();
  });
});
