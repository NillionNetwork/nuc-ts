import { describe, it } from "vitest";
import { Signer } from "#/core/signer";
import { Builder } from "#/nuc/builder";
import { REVOKE_COMMAND } from "#/nuc/payload";
import { Validator } from "#/validator/validator";
import {
  assertFailure,
  assertSuccess,
  ROOT_DIDS,
  ROOT_KEYS,
} from "#tests/helpers/assertions";

describe("Validator", () => {
  // Use a consistent root signer for all tests, derived from the test seed
  const rootSigner = Signer.fromPrivateKey(ROOT_KEYS[0]);

  it("should fail validation for an unlinked chain", async () => {
    const userSigner = Signer.generate();
    const userDid = await userSigner.getDid();

    // Create a base delegation
    let envelope = await Builder.delegation()
      .audience(userDid)
      .command("/nil")
      .subject(userDid)
      .sign(rootSigner);

    // Create a chained delegation from the base
    envelope = await Builder.delegationFrom(envelope)
      .audience(await Signer.generate().getDid())
      .sign(userSigner);

    // Create an unrelated token and push it into the proofs
    const unlinkedToken = await Builder.delegation()
      .audience(userDid)
      .command("/nil")
      .subject(userDid)
      .sign(rootSigner);

    envelope.proofs.push(unlinkedToken.nuc);

    assertFailure(envelope, Validator.UNCHAINED_PROOFS);
  });

  it("should fail validation if the chain is too long", async () => {
    const userSigner = Signer.generate();
    const userDid = await userSigner.getDid();

    // Create a chain of 3 delegations (root -> user -> user -> user)
    let envelope = await Builder.delegation()
      .audience(userDid)
      .subject(userDid)
      .command("/nil")
      .sign(rootSigner);

    // Chain the delegations, setting the audience for each new link
    envelope = await Builder.delegationFrom(envelope)
      .audience(userDid)
      .sign(userSigner);
    envelope = await Builder.delegationFrom(envelope)
      .audience(userDid)
      .sign(userSigner);
    envelope = await Builder.delegationFrom(envelope)
      .audience(userDid)
      .sign(userSigner);

    // Set max chain length to 2 (the chain has 4 tokens)
    assertFailure(envelope, Validator.CHAIN_TOO_LONG, {
      parameters: { maxChainLength: 2 },
    });
  });

  it("should fail if a command is not a valid attenuation", async () => {
    const userSigner = Signer.generate();
    const userDid = await userSigner.getDid();

    const rootEnvelope = await Builder.delegation()
      .audience(userDid)
      .subject(userDid)
      .command("/nil")
      .sign(rootSigner);

    const chainedEnvelope = await Builder.delegationFrom(rootEnvelope)
      .command("/bar") // Invalid: "/bar" is not a sub-path of "/nil"
      .audience(userDid) // A new audience is still required
      .sign(userSigner);

    assertFailure(chainedEnvelope, Validator.COMMAND_NOT_ATTENUATED);
  });

  it("should fail if subjects differ across the chain", async () => {
    const userSigner1 = Signer.generate();
    const userSigner2 = Signer.generate();
    const userDid1 = await userSigner1.getDid();
    const userDid2 = await userSigner2.getDid();

    const rootEnvelope = await Builder.delegation()
      .audience(userDid2)
      .subject(userDid1)
      .command("/nil")
      .sign(rootSigner);

    const chainedEnvelope = await Builder.delegationFrom(rootEnvelope)
      .subject(userDid2) // Invalid: subject changes mid-chain
      .audience(await Signer.generate().getDid())
      .sign(userSigner2);

    assertFailure(chainedEnvelope, Validator.DIFFERENT_SUBJECTS);
  });

  it("should fail if the issuer does not match the previous audience", async () => {
    const userSigner = Signer.generate();
    const anotherSigner = Signer.generate();
    const userDid = await userSigner.getDid();

    const rootEnvelope = await Builder.delegation()
      .audience(userDid)
      .subject(userDid)
      .command("/nil")
      .sign(rootSigner);

    const chainedEnvelope = await Builder.delegationFrom(rootEnvelope)
      .audience(await Signer.generate().getDid())
      .sign(anotherSigner); // Invalid: signed by a party that was not the audience

    assertFailure(chainedEnvelope, Validator.ISSUER_AUDIENCE_MISMATCH);
  });

  it("should fail if an invocation has an invalid audience", async () => {
    const userSigner = Signer.generate();
    const userDid = await userSigner.getDid();

    const expectedAudienceDid = await Signer.generate().getDid();
    const actualAudienceDid = await Signer.generate().getDid();

    const delegationEnvelope = await Builder.delegation()
      .audience(userDid)
      .subject(userDid)
      .command("/nil")
      .sign(rootSigner);

    const invocationEnvelope = await Builder.invocationFrom(delegationEnvelope)
      .audience(actualAudienceDid)
      .sign(userSigner);

    assertFailure(invocationEnvelope, Validator.INVALID_AUDIENCE, {
      parameters: {
        tokenRequirements: {
          type: "invocation",
          audience: expectedAudienceDid.didString,
        } as const,
      },
    });
  });

  it("should fail if a required proof is missing from the envelope", async () => {
    const userSigner = Signer.generate();
    const userDid = await userSigner.getDid();

    const rootEnvelope = await Builder.delegation()
      .audience(userDid)
      .subject(userDid)
      .command("/nil")
      .sign(rootSigner);

    const chainedEnvelope = await Builder.delegationFrom(rootEnvelope)
      .audience(userDid)
      .sign(userSigner);

    chainedEnvelope.proofs = []; // Manually remove the proof
    assertFailure(chainedEnvelope, Validator.MISSING_PROOF);
  });

  it("should fail if the policy of a parent delegation is not met", async () => {
    const userSigner = Signer.generate();
    const userDid = await userSigner.getDid();

    const rootEnvelope = await Builder.delegation()
      .policy([["==", ".args.foo", 42]])
      .subject(userDid)
      .command("/nil")
      .audience(userDid)
      .sign(rootSigner);

    const invocationEnvelope = await Builder.invocationFrom(rootEnvelope)
      .arguments({ bar: 1337 }) // Does not satisfy the policy
      .audience(await Signer.generate().getDid())
      .sign(userSigner);
    assertFailure(invocationEnvelope, Validator.POLICY_NOT_MET);
  });

  it("should fail if the root NUC is not signed by a trusted root key", async () => {
    const userSigner = Signer.generate();
    const anotherUserSigner = Signer.generate();
    const userDid = await userSigner.getDid();

    const rootEnvelope = await Builder.delegation()
      .audience(userDid)
      .subject(userDid)
      .command("/nil")
      .sign(anotherUserSigner); // Signed by a non-root key

    const chainedEnvelope = await Builder.delegationFrom(rootEnvelope)
      .audience(userDid)
      .sign(userSigner);

    assertFailure(chainedEnvelope, Validator.ROOT_KEY_SIGNATURE_MISSING, {
      rootDids: ROOT_DIDS,
    });
  });

  it("should pass validation for a valid, multi-step chain", async () => {
    const userSigner = Signer.generate();
    const userDid = await userSigner.getDid();

    const serviceDid = await Signer.generate().getDid();

    const rootDelegation = await Builder.delegation()
      .policy([
        ["==", ".args.foo", 42],
        ["==", "$.req.bar", 1337],
      ])
      .subject(userDid)
      .command("/nil")
      .audience(userDid)
      .sign(rootSigner);

    const intermediateDelegation = await Builder.delegationFrom(rootDelegation)
      .policy([["==", ".args.bar", 1337]])
      .command("/nil/bar")
      .audience(userDid)
      .sign(userSigner);

    const invocation = await Builder.invocationFrom(intermediateDelegation)
      .arguments({ foo: 42, bar: 1337 })
      .audience(serviceDid)
      .command("/nil/bar/foo")
      .sign(userSigner);

    assertSuccess(invocation, {
      parameters: {
        tokenRequirements: {
          type: "invocation",
          audience: serviceDid.didString,
        },
      },
      context: { req: { bar: 1337 } },
      rootDids: ROOT_DIDS,
    });
  });

  it("should permit a namespace jump to the REVOKE_COMMAND", async () => {
    const testRootSigner = Signer.generate();
    const userSigner = Signer.generate();
    const userDid = await userSigner.getDid();

    // 1. Root grants a normal, non-revoke capability.
    const rootDelegation = await Builder.delegation()
      .audience(userDid)
      .subject(userDid)
      .command("/nil/db/data")
      .sign(testRootSigner);

    // 2. User creates an invocation that "jumps" from the /db/data/read
    //    namespace to the /nuc/revoke namespace.
    const revocationInvocation = await Builder.invocationFrom(rootDelegation)
      .command(REVOKE_COMMAND)
      .audience(await Signer.generate().getDid()) // Fake revocation service
      .arguments({ token_hash: "any_hash_will_do_for_this_test" })
      .sign(userSigner);

    // 3. Assert that this envelope passes validation.
    //    This proves the validator's core logic correctly handles the exception
    //    for REVOKE_COMMAND, even when the builder creates the namespace jump.
    assertSuccess(revocationInvocation, {
      rootDids: [(await testRootSigner.getDid()).didString],
    });
  });
});
