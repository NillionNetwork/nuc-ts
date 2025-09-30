import { describe, it } from "vitest";
import { Keypair } from "#/core/keypair";
import { Builder } from "#/nuc/builder";
import { REVOKE_COMMAND } from "#/nuc/payload";
import {
  CHAIN_TOO_LONG,
  COMMAND_NOT_ATTENUATED,
  DIFFERENT_SUBJECTS,
  INVALID_AUDIENCE,
  ISSUER_AUDIENCE_MISMATCH,
  MISSING_PROOF,
  POLICY_NOT_MET,
  ROOT_KEY_SIGNATURE_MISSING,
  UNCHAINED_PROOFS,
} from "#/validator/validator";
import {
  assertFailure,
  assertSuccess,
  ROOT_DIDS,
  ROOT_KEYS,
} from "#tests/helpers/assertions";

describe("Validator", () => {
  // Use a consistent root keypair for all tests, derived from the test seed
  const rootKeypair = Keypair.fromBytes(ROOT_KEYS[0]);
  const rootSigner = rootKeypair.signer();

  it("should fail validation for an unlinked chain", async () => {
    const userKeypair = Keypair.generate();
    const userSigner = userKeypair.signer();

    // Create a base delegation
    let envelope = await Builder.delegation()
      .audience(userKeypair.toDid())
      .command("/nil")
      .subject(userKeypair.toDid())
      .sign(rootSigner);

    // Create a chained delegation from the base
    envelope = await Builder.delegationFrom(envelope)
      .audience(Keypair.generate().toDid())
      .sign(userSigner);

    // Create an unrelated token and push it into the proofs
    const unlinkedToken = await Builder.delegation()
      .audience(userKeypair.toDid())
      .command("/nil")
      .subject(userKeypair.toDid())
      .sign(rootSigner);

    envelope.proofs.push(unlinkedToken.nuc);

    assertFailure(envelope, UNCHAINED_PROOFS);
  });

  it("should fail validation if the chain is too long", async () => {
    const userKeypair = Keypair.generate();
    const userSigner = userKeypair.signer();

    // Create a chain of 3 delegations (root -> user -> user -> user)
    let envelope = await Builder.delegation()
      .audience(userKeypair.toDid())
      .subject(userKeypair.toDid())
      .command("/nil")
      .sign(rootSigner);

    // Chain the delegations, setting the audience for each new link
    envelope = await Builder.delegationFrom(envelope)
      .audience(userKeypair.toDid())
      .sign(userSigner);
    envelope = await Builder.delegationFrom(envelope)
      .audience(userKeypair.toDid())
      .sign(userSigner);
    envelope = await Builder.delegationFrom(envelope)
      .audience(userKeypair.toDid())
      .sign(userSigner);

    // Set max chain length to 2 (the chain has 4 tokens)
    assertFailure(envelope, CHAIN_TOO_LONG, {
      parameters: { maxChainLength: 2 },
    });
  });

  it("should fail if a command is not a valid attenuation", async () => {
    const userKeypair = Keypair.generate();
    const userSigner = userKeypair.signer();

    const rootEnvelope = await Builder.delegation()
      .audience(userKeypair.toDid())
      .subject(userKeypair.toDid())
      .command("/nil")
      .sign(rootSigner);

    const chainedEnvelope = await Builder.delegationFrom(rootEnvelope)
      .command("/bar") // Invalid: "/bar" is not a sub-path of "/nil"
      .audience(userKeypair.toDid()) // A new audience is still required
      .sign(userSigner);

    assertFailure(chainedEnvelope, COMMAND_NOT_ATTENUATED);
  });

  it("should fail if subjects differ across the chain", async () => {
    const userKeypair1 = Keypair.generate();
    const userKeypair2 = Keypair.generate();
    const userSigner2 = userKeypair2.signer();

    const rootEnvelope = await Builder.delegation()
      .audience(userKeypair2.toDid())
      .subject(userKeypair1.toDid())
      .command("/nil")
      .sign(rootSigner);

    const chainedEnvelope = await Builder.delegationFrom(rootEnvelope)
      .subject(userKeypair2.toDid()) // Invalid: subject changes mid-chain
      .audience(Keypair.generate().toDid())
      .sign(userSigner2);

    assertFailure(chainedEnvelope, DIFFERENT_SUBJECTS);
  });

  it("should fail if the issuer does not match the previous audience", async () => {
    const userKeypair = Keypair.generate();
    const anotherKeypair = Keypair.generate();
    const anotherSigner = anotherKeypair.signer();

    const rootEnvelope = await Builder.delegation()
      .audience(userKeypair.toDid())
      .subject(userKeypair.toDid())
      .command("/nil")
      .sign(rootSigner);

    const chainedEnvelope = await Builder.delegationFrom(rootEnvelope)
      .audience(Keypair.generate().toDid())
      .sign(anotherSigner); // Invalid: signed by a party that was not the audience

    assertFailure(chainedEnvelope, ISSUER_AUDIENCE_MISMATCH);
  });

  it("should fail if an invocation has an invalid audience", async () => {
    const userKeypair = Keypair.generate();
    const userSigner = userKeypair.signer();

    const expectedAudienceDid = Keypair.generate().toDid();
    const actualAudienceDid = Keypair.generate().toDid();

    const delegationEnvelope = await Builder.delegation()
      .audience(userKeypair.toDid())
      .subject(userKeypair.toDid())
      .command("/nil")
      .sign(rootSigner);

    const invocationEnvelope = await Builder.invocationFrom(delegationEnvelope)
      .audience(actualAudienceDid)
      .sign(userSigner);

    assertFailure(invocationEnvelope, INVALID_AUDIENCE, {
      parameters: {
        tokenRequirements: {
          type: "invocation",
          audience: expectedAudienceDid.didString,
        } as const,
      },
    });
  });

  it("should fail if a required proof is missing from the envelope", async () => {
    const userKeypair = Keypair.generate();
    const userSigner = userKeypair.signer();

    const rootEnvelope = await Builder.delegation()
      .audience(userKeypair.toDid())
      .subject(userKeypair.toDid())
      .command("/nil")
      .sign(rootSigner);

    const chainedEnvelope = await Builder.delegationFrom(rootEnvelope)
      .audience(userKeypair.toDid())
      .sign(userSigner);

    chainedEnvelope.proofs = []; // Manually remove the proof
    assertFailure(chainedEnvelope, MISSING_PROOF);
  });

  it("should fail if the policy of a parent delegation is not met", async () => {
    const userKeypair = Keypair.generate();
    const userSigner = userKeypair.signer();

    const rootEnvelope = await Builder.delegation()
      .policy([["==", ".args.foo", 42]])
      .subject(userKeypair.toDid())
      .command("/nil")
      .audience(userKeypair.toDid())
      .sign(rootSigner);

    const invocationEnvelope = await Builder.invocationFrom(rootEnvelope)
      .arguments({ bar: 1337 }) // Does not satisfy the policy
      .audience(Keypair.generate().toDid())
      .sign(userSigner);
    assertFailure(invocationEnvelope, POLICY_NOT_MET);
  });

  it("should fail if the root NUC is not signed by a trusted root key", async () => {
    const userKeypair = Keypair.generate();
    const anotherUserKeypair = Keypair.generate();
    const anotherUserSigner = anotherUserKeypair.signer();

    const rootEnvelope = await Builder.delegation()
      .audience(userKeypair.toDid())
      .subject(userKeypair.toDid())
      .command("/nil")
      .sign(anotherUserSigner); // Signed by a non-root key

    const chainedEnvelope = await Builder.delegationFrom(rootEnvelope)
      .audience(userKeypair.toDid())
      .sign(userKeypair.signer());

    assertFailure(chainedEnvelope, ROOT_KEY_SIGNATURE_MISSING, {
      rootDids: ROOT_DIDS,
    });
  });

  it("should pass validation for a valid, multi-step chain", async () => {
    const userKeypair = Keypair.generate();
    const userSigner = userKeypair.signer();
    const userDid = userKeypair.toDid();

    const serviceKeypair = Keypair.generate();
    const serviceDid = serviceKeypair.toDid();

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
    const rootKeypair = Keypair.generate();
    const rootSigner = rootKeypair.signer();
    const userKeypair = Keypair.generate();
    const userSigner = userKeypair.signer();

    // 1. Root grants a normal, non-revoke capability.
    const rootDelegation = await Builder.delegation()
      .audience(userKeypair.toDid())
      .subject(userKeypair.toDid())
      .command("/nil/db/data")
      .sign(rootSigner);

    // 2. User creates an invocation that "jumps" from the /db/data/read
    //    namespace to the /nuc/revoke namespace.
    const revocationInvocation = await Builder.invocationFrom(rootDelegation)
      .command(REVOKE_COMMAND)
      .audience(Keypair.generate().toDid()) // Fake revocation service
      .arguments({ token_hash: "any_hash_will_do_for_this_test" })
      .sign(userSigner);

    // 3. Assert that this envelope passes validation.
    //    This proves the validator's core logic correctly handles the exception
    //    for REVOKE_COMMAND, even when the builder creates the namespace jump.
    assertSuccess(revocationInvocation, {
      rootDids: [rootKeypair.toDid().didString],
    });
  });
});
