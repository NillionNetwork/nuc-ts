import { secp256k1 } from "@noble/curves/secp256k1";
import { describe, it } from "vitest";
import * as did from "#/core/did/did";
import { Keypair } from "#/core/keypair";
import {
  Builder,
  type DelegationBuilder,
  type InvocationBuilder,
} from "#/nuc/builder";
import {
  CHAIN_TOO_LONG,
  COMMAND_NOT_ATTENUATED,
  DIFFERENT_SUBJECTS,
  INVALID_AUDIENCE,
  INVALID_SIGNATURES,
  ISSUER_AUDIENCE_MISMATCH,
  MISSING_PROOF,
  POLICY_NOT_MET,
  ROOT_KEY_SIGNATURE_MISSING,
  UNCHAINED_PROOFS,
} from "#/nuc/validate/index";
import { Asserter, ROOT_DIDS, ROOT_KEYS } from "./assertions";

function delegation(privateKey: Uint8Array): DelegationBuilder {
  // Create DID objects using the new factory function
  const defaultAudience = did.fromPublicKey(
    new Uint8Array(Array(33).fill(0xde)),
  );
  const publicDid = did.fromPublicKey(secp256k1.getPublicKey(privateKey));

  return Builder.delegation().audience(defaultAudience).subject(publicDid);
}

function invocation(privateKey: Uint8Array): InvocationBuilder {
  // Create DID objects using the new factory function
  const defaultAudience = did.fromPublicKey(
    new Uint8Array(Array(33).fill(0xde)),
  );
  const publicDid = did.fromPublicKey(secp256k1.getPublicKey(privateKey));

  return Builder.invocation().audience(defaultAudience).subject(publicDid);
}

describe("Validator", () => {
  const rootKeypair = Keypair.fromBytes(ROOT_KEYS[0]);

  it("unlinked chain", () => {
    const key = secp256k1.utils.randomSecretKey();
    const userKeypair = Keypair.fromBytes(key);
    const base = delegation(key).command("/nil");

    let envelope = base.build(rootKeypair);
    envelope = base.proof(envelope).build(userKeypair);

    const unlinkedToken = base.build(rootKeypair);
    envelope.proofs.push(unlinkedToken.nuc);

    new Asserter().assertFailure(envelope, UNCHAINED_PROOFS);
  });

  it("chain too long", () => {
    const key = secp256k1.utils.randomSecretKey();
    const userKeypair = Keypair.fromBytes(key);

    const builders = [
      delegation(key).command("/nil"),
      delegation(key).command("/nil"),
      delegation(key).command("/nil"),
    ];

    let envelope = Builder.delegation()
      .audience(userKeypair.toDid())
      .subject(userKeypair.toDid())
      .command("/nil")
      .build(rootKeypair);

    for (const builder of builders) {
      envelope = builder.proof(envelope).build(userKeypair);
    }

    const parameters = { maxChainLength: 2 };
    new Asserter({ parameters }).assertFailure(envelope, CHAIN_TOO_LONG);
  });

  it("command not attenuated", () => {
    const key = secp256k1.utils.randomSecretKey();
    const userKeypair = Keypair.fromBytes(key);

    const root = delegation(key).command("/nil").audience(userKeypair.toDid());
    const last = delegation(key).command("/bar");

    let envelope = root.build(rootKeypair);
    envelope = last.proof(envelope).build(userKeypair);

    new Asserter().assertFailure(envelope, COMMAND_NOT_ATTENUATED);
  });

  it("different subjects", () => {
    const key1 = secp256k1.utils.randomSecretKey();
    const key2 = secp256k1.utils.randomSecretKey();
    const userKeypair2 = Keypair.fromBytes(key2);

    const root = delegation(key1)
      .command("/nil")
      .audience(userKeypair2.toDid());
    const last = delegation(key2).command("/nil");

    let envelope = root.build(rootKeypair);
    envelope = last.proof(envelope).build(userKeypair2);

    new Asserter().assertFailure(envelope, DIFFERENT_SUBJECTS);
  });

  it("audience mismatch", () => {
    const key = secp256k1.utils.randomSecretKey();
    const userKeypair = Keypair.fromBytes(key);
    const root = delegation(key)
      .command("/nil")
      .audience(did.fromPublicKey(new Uint8Array(Array(33).fill(0xaa))));
    const last = delegation(key).command("/nil");

    let envelope = root.build(rootKeypair);
    envelope = last.proof(envelope).build(userKeypair);

    new Asserter().assertFailure(envelope, ISSUER_AUDIENCE_MISMATCH);
  });

  it("invalid audience invocation", () => {
    const key = secp256k1.utils.randomSecretKey();
    const userKeypair = Keypair.fromBytes(key);

    const expectedAudience = did.serialize(
      did.fromPublicKey(new Uint8Array(Array(33).fill(0xaa))),
    );
    const actualAudience = did.fromPublicKey(
      new Uint8Array(Array(33).fill(0xbb)),
    );

    const root = delegation(key).command("/nil").audience(userKeypair.toDid());
    const last = invocation(key).command("/nil").audience(actualAudience);

    let envelope = root.build(rootKeypair);
    envelope = last.proof(envelope).build(userKeypair);

    const parameters = {
      tokenRequirements: {
        type: "invocation",
        audience: expectedAudience,
      } as const,
    };
    new Asserter({ parameters }).assertFailure(envelope, INVALID_AUDIENCE);
  });

  it("invalid signature", () => {
    const key = secp256k1.utils.randomSecretKey();
    const envelope = delegation(key).command("/nil").build(rootKeypair);

    // Tamper with the signature
    envelope.nuc.signature[0] ^= 1;

    new Asserter().assertFailure(envelope, INVALID_SIGNATURES);
  });

  it("missing proof", () => {
    const key = secp256k1.utils.randomSecretKey();
    const userKeypair = Keypair.fromBytes(key);
    const base = delegation(key).command("/nil").audience(userKeypair.toDid());

    let envelope = base.build(rootKeypair);
    envelope = base.proof(envelope).build(userKeypair);

    // Remove the proof from the envelope
    envelope.proofs = [];

    new Asserter().assertFailure(envelope, MISSING_PROOF);
  });

  it("policy not met", () => {
    const key = secp256k1.utils.randomSecretKey();
    const userKeypair = Keypair.fromBytes(key);
    const subject = userKeypair.toDid();

    const root = Builder.delegation()
      .policy([["==", ".args.foo", 42]])
      .subject(subject)
      .command("/nil")
      .audience(userKeypair.toDid());

    let envelope = root.build(rootKeypair);

    // Using the new invoking method for cleaner API
    envelope = Builder.invoking(envelope)
      .arguments({ bar: 1337 })
      .audience(Keypair.generate().toDid())
      .build(userKeypair);

    new Asserter().assertFailure(envelope, POLICY_NOT_MET);
  });

  it("root key signature missing", () => {
    const key = secp256k1.utils.randomSecretKey();
    const userKeypair = Keypair.fromBytes(key);

    const root = delegation(key).command("/nil").audience(userKeypair.toDid());
    const last = delegation(key).command("/nil");

    let envelope = root.build(userKeypair);
    envelope = last.proof(envelope).build(userKeypair);
    new Asserter({ rootDids: ROOT_DIDS }).assertFailure(
      envelope,
      ROOT_KEY_SIGNATURE_MISSING,
    );
  });

  it("valid chain", () => {
    const subjectKey = secp256k1.utils.randomSecretKey();
    const subjectKeypair = Keypair.fromBytes(subjectKey);
    const subject = subjectKeypair.toDid();

    const rpcDid = did.fromPublicKey(new Uint8Array(Array(33).fill(33)));

    const root = Builder.delegation()
      .policy([
        ["==", ".args.foo", 42],
        ["==", "$.req.bar", 1337],
      ])
      .subject(subject)
      .command("/nil")
      .audience(subjectKeypair.toDid());

    const intermediate = Builder.delegation()
      .policy([["==", ".args.bar", 1337]])
      .subject(subject)
      .command("/nil/bar")
      .audience(subjectKeypair.toDid());

    const last = Builder.invocation()
      .arguments({ foo: 42, bar: 1337 })
      .subject(subject)
      .audience(rpcDid)
      .command("/nil/bar/foo");

    let envelope = root.build(rootKeypair);
    envelope = intermediate.proof(envelope).build(subjectKeypair);
    envelope = last.proof(envelope).build(subjectKeypair);

    const parameters = {
      tokenRequirements: {
        type: "invocation",
        audience: did.serialize(rpcDid),
      } as const,
    };
    const context = { req: { bar: 1337 } };
    new Asserter({ parameters, context }).assertSuccess(envelope);
  });
});
