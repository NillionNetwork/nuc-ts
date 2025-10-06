import { type HDNodeWallet, Wallet } from "ethers";
import { beforeEach, describe, expect, it } from "vitest";
import type { Signer as NucSigner } from "#/core/signer";
import { Signer } from "#/core/signer";
import { Builder } from "#/nuc/builder";
import { Codec } from "#/nuc/codec";
import { validateNucSignature } from "#/validator/signatures";

describe("Web3 Signer (EIP-712)", () => {
  let wallet: HDNodeWallet;
  let web3Signer: NucSigner;

  beforeEach(async () => {
    wallet = Wallet.createRandom();
    web3Signer = Signer.fromWeb3(wallet);
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
    expect(() => validateNucSignature(envelope.nuc)).not.toThrow();
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
    expect(() => validateNucSignature(invocation.nuc)).not.toThrow();
    expect(() => validateNucSignature(invocation.proofs[0])).not.toThrow();
  });

  it("can validate a metamask nuc", async () => {
    const rawToken =
      "eyJ0eXAiOiJudWMrZWlwNzEyIiwiYWxnIjoiRVMyNTZLIiwidmVyIjoiMS4wLjAiLCJtZXRhIjp7ImRvbWFpbiI6eyJuYW1lIjoiTlVDIiwidmVyc2lvbiI6IjEiLCJjaGFpbklkIjoxfSwicHJpbWFyeVR5cGUiOiJOdWNQYXlsb2FkIiwidHlwZXMiOnsiTnVjUGF5bG9hZCI6W3sibmFtZSI6ImlzcyIsInR5cGUiOiJzdHJpbmcifSx7Im5hbWUiOiJhdWQiLCJ0eXBlIjoic3RyaW5nIn0seyJuYW1lIjoic3ViIiwidHlwZSI6InN0cmluZyJ9LHsibmFtZSI6ImNtZCIsInR5cGUiOiJzdHJpbmcifSx7Im5hbWUiOiJwb2wiLCJ0eXBlIjoic3RyaW5nIn0seyJuYW1lIjoiYXJncyIsInR5cGUiOiJzdHJpbmcifSx7Im5hbWUiOiJuYmYiLCJ0eXBlIjoidWludDI1NiJ9LHsibmFtZSI6ImV4cCIsInR5cGUiOiJ1aW50MjU2In0seyJuYW1lIjoibm9uY2UiLCJ0eXBlIjoic3RyaW5nIn0seyJuYW1lIjoicHJmIiwidHlwZSI6InN0cmluZ1tdIn1dfX19.eyJpc3MiOiJkaWQ6ZXRocjoweGRGYjc2RUQzNzg5ZkI5ZTRkNjc2YmU0YzA2MDgzOTVhNDczMzdDZDkiLCJhdWQiOiJkaWQ6a2V5OnpRM3Noa0FSTDVKQUVCYkxmOGNxUEtwazNzVUFmYUhzMkZhTXoyaWtKZ3VhNk1qR3ciLCJzdWIiOiJkaWQ6ZXRocjoweGRGYjc2RUQzNzg5ZkI5ZTRkNjc2YmU0YzA2MDgzOTVhNDczMzdDZDkiLCJjbWQiOiIvbmlsL2F1dGgvcGF5bWVudHMvdmFsaWRhdGUiLCJhcmdzIjp7fSwibm9uY2UiOiI2OTQ0ODQyYTY4ZTQxNWI5ZDliNWVjZDRlMjVlYmQwZSIsInByZiI6W119.8axgm1t_x0XubgltP8PsptKnXmUGctlc60gpSxw8N_N3Vr742tvtKb8iNlbhMvv-P7ShiBnpgvc6gmVASDyi0xw";
    const envelope = Codec.decodeBase64Url(rawToken);
    expect(() => validateNucSignature(envelope.nuc)).not.toThrow();
  });
});
