import { hexToBytes } from "@noble/hashes/utils.js";
import { Wallet } from "ethers";
import { describe, it } from "vitest";
import * as ethr from "#/core/did/ethr";
import type { Signer as SignerType } from "#/core/signer";
import { Signer } from "#/core/signer";
import { Builder } from "#/nuc/builder";
import { NucHeaders } from "#/nuc/header";
import { assertSuccess } from "#tests/helpers/assertions";

describe("heterogeneous nuc chain", () => {
  it("should validate a heterogeneous chain: did:key -> did:ethr -> did:nil", async ({
    expect,
  }) => {
    // Phase 1 - Actors
    // A. The root of trust, using did:key
    const rootSigner = Signer.generate();
    const rootDid = await rootSigner.getDid();

    // B. An intermediate user with an Ethereum wallet
    const userWallet = Wallet.createRandom();
    const userDid = ethr.fromAddress(userWallet.address);
    const userSigner: SignerType = {
      header: NucHeaders.v1,
      getDid: async () => userDid,
      sign: async (data) => {
        const signatureHex = await userWallet.signMessage(data);
        const cleanHex = signatureHex.startsWith("0x")
          ? signatureHex.slice(2)
          : signatureHex;
        return hexToBytes(cleanHex);
      },
    };

    // C. A legacy service that the user delegates a sub-capability to
    const legacySvcSigner = Signer.generate("nil");
    const legacySvcDid = await legacySvcSigner.getDid();

    // D. The final service that receives the invocation
    const finalSvcDid = await Signer.generate().getDid();

    // Phase 2 - Build the chain
    // 1. Root (did:key) delegates to User (did:ethr)
    const rootToUserDelegation = await Builder.delegation()
      .audience(userDid)
      .subject(userDid)
      .command("/nil/db/data")
      .sign(rootSigner);

    // 2. User (did:ethr) delegates to LegacySvc (did:nil)
    const userToLegacySvcDelegation = await Builder.delegationFrom(
      rootToUserDelegation,
    )
      .audience(legacySvcDid)
      .command("/nil/db/data/find")
      .sign(userSigner);

    // 3. LegacySvc (did:nil) invokes the command for the FinalSvc
    const invocation = await Builder.invocationFrom(userToLegacySvcDelegation)
      .audience(finalSvcDid)
      .arguments({ id: 123 })
      .sign(legacySvcSigner);

    // Phase 3 - Validation
    assertSuccess(invocation, { rootDids: [rootDid.didString] });
    expect(invocation.proofs).toHaveLength(2);
  });
});
