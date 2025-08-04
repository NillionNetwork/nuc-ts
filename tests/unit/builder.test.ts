import { describe, it } from "vitest";
import { Keypair } from "#/core/keypair";
import { Signers } from "#/core/signer";
import { Builder } from "#/nuc/builder";
import {
  isDelegationPayload,
  isInvocationPayload,
  REVOKE_COMMAND,
} from "#/nuc/payload";
import { validateSignature } from "#/validator/signatures";

describe("Builder", () => {
  const keypair = Keypair.generate();
  const aud = Keypair.generate().toDid();
  const sub = Keypair.generate().toDid();

  it("builds a valid delegation token", async ({ expect }) => {
    const envelope = await Builder.delegation()
      .policy([["==", ".command", "/db/read"]])
      .addPolicy(["!=", ".resource", "users"])
      .audience(aud)
      .subject(sub)
      .command(REVOKE_COMMAND)
      .build(Signers.fromKeypair(keypair));

    validateSignature(envelope.nuc);
    const payload = envelope.nuc.payload;

    expect(isDelegationPayload(payload)).toBe(true);
    if (!isDelegationPayload(payload)) return;

    expect(payload.pol).toHaveLength(2);
  });

  it("builds a valid invocation token", async ({ expect }) => {
    const envelope = await Builder.invocation()
      .arguments({ action: "read" })
      .addArgument("resourceId", 123)
      .audience(aud)
      .subject(sub)
      .command("/db/read")
      .build(Signers.fromKeypair(keypair));

    validateSignature(envelope.nuc);
    const payload = envelope.nuc.payload;

    expect(isInvocationPayload(payload)).toBe(true);
    if (!isInvocationPayload(payload)) return;

    expect(payload.args).toEqual({ action: "read", resourceId: 123 });
  });

  it("builds a chained token using delegating()", async ({ expect }) => {
    const rootKeypair = Keypair.generate();
    const userKeypair = Keypair.generate();

    const rootEnvelope = await Builder.delegation()
      .policy([["==", ".command", "/db/read"]])
      .audience(userKeypair.toDid())
      .subject(userKeypair.toDid())
      .command("/db/read")
      .build(Signers.fromKeypair(rootKeypair));

    const chainedEnvelope = await Builder.delegating(rootEnvelope)
      .audience(aud) // new audience
      .build(Signers.fromKeypair(userKeypair)); // signed by user

    expect(chainedEnvelope.proofs).toHaveLength(1);
    expect(chainedEnvelope.nuc.payload.prf).toHaveLength(1);

    const payload = chainedEnvelope.nuc.payload;
    expect(payload.iss.didString).toEqual(userKeypair.toDid().didString);
    expect(payload.sub.didString).toEqual(userKeypair.toDid().didString); // Inherited
    expect(payload.cmd).toBe("/db/read"); // Inherited
  });

  it("builds an invocation token from a delegation using invoking()", async ({
    expect,
  }) => {
    const rootKeypair = Keypair.generate();
    const userKeypair = Keypair.generate();

    // Create a parent delegation
    const delegationEnvelope = await Builder.delegation()
      .policy([["==", ".command", "/db/read"]])
      .audience(userKeypair.toDid())
      .subject(userKeypair.toDid())
      .command("/db/read")
      .build(Signers.fromKeypair(rootKeypair));

    // Create an invocation from the delegation
    const invocationEnvelope = await Builder.invoking(delegationEnvelope)
      .audience(aud) // new audience
      .addArgument("action", "read")
      .addArgument("resourceId", 456)
      .build(Signers.fromKeypair(userKeypair)); // signed by user

    expect(invocationEnvelope.proofs).toHaveLength(1);
    expect(invocationEnvelope.nuc.payload.prf).toHaveLength(1);

    const payload = invocationEnvelope.nuc.payload;
    expect(isInvocationPayload(payload)).toBe(true);
    if (!isInvocationPayload(payload)) return;

    // Verify inherited properties
    expect(payload.sub.didString).toEqual(userKeypair.toDid().didString); // Inherited from delegation
    expect(payload.cmd).toBe("/db/read"); // Inherited from delegation

    // Verify invocation-specific properties
    expect(payload.iss.didString).toEqual(userKeypair.toDid().didString);
    expect(payload.args).toEqual({ action: "read", resourceId: 456 });
  });
});
