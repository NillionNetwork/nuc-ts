import { describe, it } from "vitest";
import { Keypair } from "#/core/keypair";
import { Builder } from "#/nuc/builder";
import { Codec } from "#/nuc/codec";
import { Payload, REVOKE_COMMAND } from "#/nuc/payload";

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
      .sign(keypair.signer());

    const payload = envelope.nuc.payload;

    expect(Payload.isDelegationPayload(payload)).toBe(true);
    if (!Payload.isDelegationPayload(payload)) return;

    expect(payload.pol).toHaveLength(2);
  });

  it("builds a valid invocation token", async ({ expect }) => {
    const envelope = await Builder.invocation()
      .arguments({ action: "read" })
      .addArgument("resourceId", 123)
      .audience(aud)
      .subject(sub)
      .command("/db/read")
      .sign(keypair.signer());

    const payload = envelope.nuc.payload;

    expect(Payload.isInvocationPayload(payload)).toBe(true);
    if (!Payload.isInvocationPayload(payload)) return;

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
      .sign(rootKeypair.signer());

    const chainedEnvelope = await Builder.delegationFrom(rootEnvelope)
      .audience(aud) // new audience
      .sign(userKeypair.signer()); // signed by user

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
      .sign(rootKeypair.signer());

    // Create an invocation from the delegation
    const invocationEnvelope = await Builder.invocationFrom(delegationEnvelope)
      .audience(aud) // new audience
      .addArgument("action", "read")
      .addArgument("resourceId", 456)
      .sign(userKeypair.signer()); // signed by user

    expect(invocationEnvelope.proofs).toHaveLength(1);
    expect(invocationEnvelope.nuc.payload.prf).toHaveLength(1);

    const payload = invocationEnvelope.nuc.payload;
    expect(Payload.isInvocationPayload(payload)).toBe(true);
    if (!Payload.isInvocationPayload(payload)) return;

    // Verify inherited properties
    expect(payload.sub.didString).toEqual(userKeypair.toDid().didString); // Inherited from delegation
    expect(payload.cmd).toBe("/db/read"); // Inherited from delegation

    // Verify invocation-specific properties
    expect(payload.iss.didString).toEqual(userKeypair.toDid().didString);
    expect(payload.args).toEqual({ action: "read", resourceId: 456 });
  });
});

describe("Builder Ergonomics", () => {
  const rootKeypair = Keypair.generate();
  const rootSigner = rootKeypair.signer();
  const userKeypair = Keypair.generate();
  const userSigner = userKeypair.signer();
  const serviceDid = Keypair.generate().toDid();

  it("should sign and serialize a delegation in one step", async ({
    expect,
  }) => {
    const serializedToken = await Builder.delegation()
      .audience(userKeypair.toDid())
      .subject(userKeypair.toDid())
      .command("/test")
      .signAndSerialize(rootSigner);

    expect(typeof serializedToken).toBe("string");
    const decoded = Codec.decodeBase64Url(serializedToken);
    expect(decoded.nuc.payload.aud.didString).toBe(
      userKeypair.toDid().didString,
    );
  });

  it("should create a chained delegation from a string", async ({ expect }) => {
    const rootDelegationString = await Builder.delegation()
      .audience(userKeypair.toDid())
      .subject(userKeypair.toDid())
      .command("/test/delegate")
      .signAndSerialize(rootSigner);

    const chainedDelegationString = await Builder.delegationFromString(
      rootDelegationString,
    )
      .audience(serviceDid)
      .signAndSerialize(userSigner);

    const decoded = Codec.decodeBase64Url(chainedDelegationString);
    expect(decoded.proofs).toHaveLength(1);
    expect(decoded.nuc.payload.iss.didString).toBe(
      userKeypair.toDid().didString,
    );
    expect(decoded.proofs[0].payload.iss.didString).toBe(
      rootKeypair.toDid().didString,
    );
  });

  it("should create an invocation from a string", async ({ expect }) => {
    const rootDelegationString = await Builder.delegation()
      .audience(userKeypair.toDid())
      .subject(userKeypair.toDid())
      .command("/test/invoke")
      .signAndSerialize(rootSigner);

    const invocationString = await Builder.invocationFromString(
      rootDelegationString,
    )
      .audience(serviceDid)
      .arguments({ foo: "bar" })
      .signAndSerialize(userSigner);

    const decoded = Codec.decodeBase64Url(invocationString);
    expect(decoded.proofs).toHaveLength(1);
    expect(decoded.nuc.payload.iss.didString).toBe(
      userKeypair.toDid().didString,
    );
    expect(Payload.isInvocationPayload(decoded.nuc.payload)).toBe(true);
    if (Payload.isInvocationPayload(decoded.nuc.payload)) {
      expect(decoded.nuc.payload.args).toEqual({ foo: "bar" });
    }
  });
});
