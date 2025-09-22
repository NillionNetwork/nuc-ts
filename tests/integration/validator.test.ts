import { describe, it } from "vitest";
import { Did } from "#/core/did/did";
import { Keypair } from "#/core/keypair";
import { Signer } from "#/core/signer";
import { Builder } from "#/nuc/builder";
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
} from "#/validator";
import { Asserter, ROOT_DIDS, ROOT_KEYS } from "./assertions";

describe("Validator", () => {
  // Use a consistent root keypair for all tests, derived from the test seed
  const rootKeypair = Keypair.fromBytes(ROOT_KEYS[0]);
  const rootSigner = Signer.fromKeypair(rootKeypair);

  it("should fail validation for an unlinked chain", async () => {
    const userKeypair = Keypair.generate();
    const userSigner = Signer.fromKeypair(userKeypair);

    // Create a base delegation
    let envelope = await Builder.delegation()
      .audience(userKeypair.toDid())
      .command("/nil")
      .subject(userKeypair.toDid())
      .build(rootSigner);

    // Create a chained delegation from the base
    envelope = await Builder.delegating(envelope)
      .audience(Keypair.generate().toDid())
      .build(userSigner);

    // Create an unrelated token and push it into the proofs
    const unlinkedToken = await Builder.delegation()
      .audience(userKeypair.toDid())
      .command("/nil")
      .subject(userKeypair.toDid())
      .build(rootSigner);

    envelope.proofs.push(unlinkedToken.nuc);

    new Asserter().assertFailure(envelope, UNCHAINED_PROOFS);
  });

  it("should fail validation if the chain is too long", async () => {
    const userKeypair = Keypair.generate();
    const userSigner = Signer.fromKeypair(userKeypair);

    // Create a chain of 3 delegations (root -> user -> user -> user)
    let envelope = await Builder.delegation()
      .audience(userKeypair.toDid())
      .subject(userKeypair.toDid())
      .command("/nil")
      .build(rootSigner);

    // Chain the delegations, setting the audience for each new link
    envelope = await Builder.delegating(envelope)
      .audience(userKeypair.toDid())
      .build(userSigner);
    envelope = await Builder.delegating(envelope)
      .audience(userKeypair.toDid())
      .build(userSigner);
    envelope = await Builder.delegating(envelope)
      .audience(userKeypair.toDid())
      .build(userSigner);

    // Set max chain length to 2 (the chain has 4 tokens)
    const parameters = { maxChainLength: 2 };
    new Asserter({ parameters }).assertFailure(envelope, CHAIN_TOO_LONG);
  });

  it("should fail if a command is not a valid attenuation", async () => {
    const userKeypair = Keypair.generate();
    const userSigner = Signer.fromKeypair(userKeypair);

    const rootEnvelope = await Builder.delegation()
      .audience(userKeypair.toDid())
      .subject(userKeypair.toDid())
      .command("/nil")
      .build(rootSigner);

    const chainedEnvelope = await Builder.delegating(rootEnvelope)
      .command("/bar") // Invalid: "/bar" is not a sub-path of "/nil"
      .audience(userKeypair.toDid()) // A new audience is still required
      .build(userSigner);

    new Asserter().assertFailure(chainedEnvelope, COMMAND_NOT_ATTENUATED);
  });

  it("should fail if subjects differ across the chain", async () => {
    const userKeypair1 = Keypair.generate();
    const userKeypair2 = Keypair.generate();
    const userSigner2 = Signer.fromKeypair(userKeypair2);

    const rootEnvelope = await Builder.delegation()
      .audience(userKeypair2.toDid())
      .subject(userKeypair1.toDid())
      .command("/nil")
      .build(rootSigner);

    const chainedEnvelope = await Builder.delegating(rootEnvelope)
      .subject(userKeypair2.toDid()) // Invalid: subject changes mid-chain
      .audience(Keypair.generate().toDid())
      .build(userSigner2);

    new Asserter().assertFailure(chainedEnvelope, DIFFERENT_SUBJECTS);
  });

  it("should fail if the issuer does not match the previous audience", async () => {
    const userKeypair = Keypair.generate();
    const anotherKeypair = Keypair.generate();
    const anotherSigner = Signer.fromKeypair(anotherKeypair);

    const rootEnvelope = await Builder.delegation()
      .audience(userKeypair.toDid())
      .subject(userKeypair.toDid())
      .command("/nil")
      .build(rootSigner);

    const chainedEnvelope = await Builder.delegating(rootEnvelope)
      .audience(Keypair.generate().toDid())
      .build(anotherSigner); // Invalid: signed by a party that was not the audience

    new Asserter().assertFailure(chainedEnvelope, ISSUER_AUDIENCE_MISMATCH);
  });

  it("should fail if an invocation has an invalid audience", async () => {
    const userKeypair = Keypair.generate();
    const userSigner = Signer.fromKeypair(userKeypair);

    const expectedAudienceDid = Keypair.generate().toDid();
    const actualAudienceDid = Keypair.generate().toDid();

    const delegationEnvelope = await Builder.delegation()
      .audience(userKeypair.toDid())
      .subject(userKeypair.toDid())
      .command("/nil")
      .build(rootSigner);

    const invocationEnvelope = await Builder.invoking(delegationEnvelope)
      .audience(actualAudienceDid)
      .build(userSigner);

    const parameters = {
      tokenRequirements: {
        type: "invocation",
        audience: Did.serialize(expectedAudienceDid),
      } as const,
    };
    new Asserter({ parameters }).assertFailure(
      invocationEnvelope,
      INVALID_AUDIENCE,
    );
  });

  it("should fail if a required proof is missing from the envelope", async () => {
    const userKeypair = Keypair.generate();
    const userSigner = Signer.fromKeypair(userKeypair);

    const rootEnvelope = await Builder.delegation()
      .audience(userKeypair.toDid())
      .subject(userKeypair.toDid())
      .command("/nil")
      .build(rootSigner);

    const chainedEnvelope = await Builder.delegating(rootEnvelope)
      .audience(userKeypair.toDid())
      .build(userSigner);

    chainedEnvelope.proofs = []; // Manually remove the proof

    new Asserter().assertFailure(chainedEnvelope, MISSING_PROOF);
  });

  it("should fail if the policy of a parent delegation is not met", async () => {
    const userKeypair = Keypair.generate();
    const userSigner = Signer.fromKeypair(userKeypair);

    const rootEnvelope = await Builder.delegation()
      .policy([["==", ".args.foo", 42]])
      .subject(userKeypair.toDid())
      .command("/nil")
      .audience(userKeypair.toDid())
      .build(rootSigner);

    const invocationEnvelope = await Builder.invoking(rootEnvelope)
      .arguments({ bar: 1337 }) // Does not satisfy the policy
      .audience(Keypair.generate().toDid())
      .build(userSigner);

    new Asserter().assertFailure(invocationEnvelope, POLICY_NOT_MET);
  });

  it("should fail if the root NUC is not signed by a trusted root key", async () => {
    const userKeypair = Keypair.generate();
    const anotherUserKeypair = Keypair.generate();
    const anotherUserSigner = Signer.fromKeypair(anotherUserKeypair);

    const rootEnvelope = await Builder.delegation()
      .audience(userKeypair.toDid())
      .subject(userKeypair.toDid())
      .command("/nil")
      .build(anotherUserSigner); // Signed by a non-root key

    const chainedEnvelope = await Builder.delegating(rootEnvelope)
      .audience(userKeypair.toDid())
      .build(Signer.fromKeypair(userKeypair));

    new Asserter({ rootDids: ROOT_DIDS }).assertFailure(
      chainedEnvelope,
      ROOT_KEY_SIGNATURE_MISSING,
    );
  });

  it("should pass validation for a valid, multi-step chain", async () => {
    const userKeypair = Keypair.generate();
    const userSigner = Signer.fromKeypair(userKeypair);
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
      .build(rootSigner);

    const intermediateDelegation = await Builder.delegating(rootDelegation)
      .policy([["==", ".args.bar", 1337]])
      .command("/nil/bar")
      .audience(userDid)
      .build(userSigner);

    const invocation = await Builder.invoking(intermediateDelegation)
      .arguments({ foo: 42, bar: 1337 })
      .audience(serviceDid)
      .command("/nil/bar/foo")
      .build(userSigner);

    const parameters = {
      tokenRequirements: {
        type: "invocation",
        audience: Did.serialize(serviceDid),
      } as const,
    };
    const context = { req: { bar: 1337 } };

    new Asserter({ parameters, context, rootDids: ROOT_DIDS }).assertSuccess(
      invocation,
    );
  });
});
