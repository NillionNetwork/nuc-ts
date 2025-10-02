import { describe, it } from "vitest";
import { Signer } from "#/core/signer";
import { Builder } from "#/nuc/builder";
import { Codec } from "#/nuc/codec";
import { Payload, REVOKE_COMMAND } from "#/nuc/payload";

describe("Builder", () => {
  const signer = Signer.generate();
  const audSigner = Signer.generate();
  const subSigner = Signer.generate();

  it("builds a valid delegation token", async ({ expect }) => {
    const aud = await audSigner.getDid();
    const sub = await subSigner.getDid();

    const envelope = await Builder.delegation()
      .policy([["==", ".command", "/db/read"]])
      .addPolicy(["!=", ".resource", "users"])
      .audience(aud)
      .subject(sub)
      .command(REVOKE_COMMAND)
      .sign(signer);

    const payload = envelope.nuc.payload;

    expect(Payload.isDelegationPayload(payload)).toBe(true);
    if (!Payload.isDelegationPayload(payload)) return;

    expect(payload.pol).toHaveLength(2);
  });

  it("builds a valid invocation token", async ({ expect }) => {
    const aud = await audSigner.getDid();
    const sub = await subSigner.getDid();

    const envelope = await Builder.invocation()
      .arguments({ action: "read" })
      .addArgument("resourceId", 123)
      .audience(aud)
      .subject(sub)
      .command("/db/read")
      .sign(signer);

    const payload = envelope.nuc.payload;

    expect(Payload.isInvocationPayload(payload)).toBe(true);
    if (!Payload.isInvocationPayload(payload)) return;

    expect(payload.args).toEqual({ action: "read", resourceId: 123 });
  });

  it("builds a chained token using delegating()", async ({ expect }) => {
    const rootSigner = Signer.generate();
    const userSigner = Signer.generate();
    const userDid = await userSigner.getDid();
    const aud = await audSigner.getDid();

    const rootEnvelope = await Builder.delegation()
      .policy([["==", ".command", "/db/read"]])
      .audience(userDid)
      .subject(userDid)
      .command("/db/read")
      .sign(rootSigner);

    const chainedEnvelope = await Builder.delegationFrom(rootEnvelope)
      .audience(aud) // new audience
      .sign(userSigner); // signed by user

    expect(chainedEnvelope.proofs).toHaveLength(1);
    expect(chainedEnvelope.nuc.payload.prf).toHaveLength(1);

    const payload = chainedEnvelope.nuc.payload;
    expect(payload.iss.didString).toEqual(userDid.didString);
    expect(payload.sub.didString).toEqual(userDid.didString); // Inherited
    expect(payload.cmd).toBe("/db/read"); // Inherited
  });

  it("builds an invocation token from a delegation using invoking()", async ({
    expect,
  }) => {
    const rootSigner = Signer.generate();
    const userSigner = Signer.generate();
    const userDid = await userSigner.getDid();
    const aud = await audSigner.getDid();

    // Create a parent delegation
    const delegationEnvelope = await Builder.delegation()
      .policy([["==", ".command", "/db/read"]])
      .audience(userDid)
      .subject(userDid)
      .command("/db/read")
      .sign(rootSigner);

    // Create an invocation from the delegation
    const invocationEnvelope = await Builder.invocationFrom(delegationEnvelope)
      .audience(aud) // new audience
      .addArgument("action", "read")
      .addArgument("resourceId", 456)
      .sign(userSigner); // signed by user

    expect(invocationEnvelope.proofs).toHaveLength(1);
    expect(invocationEnvelope.nuc.payload.prf).toHaveLength(1);

    const payload = invocationEnvelope.nuc.payload;
    expect(Payload.isInvocationPayload(payload)).toBe(true);
    if (!Payload.isInvocationPayload(payload)) return;

    // Verify inherited properties
    expect(payload.sub.didString).toEqual(userDid.didString); // Inherited from delegation
    expect(payload.cmd).toBe("/db/read"); // Inherited from delegation

    // Verify invocation-specific properties
    expect(payload.iss.didString).toEqual(userDid.didString);
    expect(payload.args).toEqual({ action: "read", resourceId: 456 });
  });
});

describe("Builder Ergonomics", () => {
  const rootSigner = Signer.generate();
  const userSigner = Signer.generate();
  const serviceSigner = Signer.generate();

  it("should sign and serialize a delegation in one step", async ({
    expect,
  }) => {
    const userDid = await userSigner.getDid();

    const serializedToken = await Builder.delegation()
      .audience(userDid)
      .subject(userDid)
      .command("/test")
      .signAndSerialize(rootSigner);

    expect(typeof serializedToken).toBe("string");
    const decoded = Codec.decodeBase64Url(serializedToken);
    expect(decoded.nuc.payload.aud.didString).toBe(userDid.didString);
  });

  it("should create a chained delegation from a string", async ({ expect }) => {
    const userDid = await userSigner.getDid();
    const serviceDid = await serviceSigner.getDid();
    const rootDid = await rootSigner.getDid();

    const rootDelegationString = await Builder.delegation()
      .audience(userDid)
      .subject(userDid)
      .command("/test/delegate")
      .signAndSerialize(rootSigner);

    const chainedDelegationString = await Builder.delegationFromString(
      rootDelegationString,
    )
      .audience(serviceDid)
      .signAndSerialize(userSigner);

    const decoded = Codec.decodeBase64Url(chainedDelegationString);
    expect(decoded.proofs).toHaveLength(1);
    expect(decoded.nuc.payload.iss.didString).toBe(userDid.didString);
    expect(decoded.proofs[0].payload.iss.didString).toBe(rootDid.didString);
  });

  it("should create an invocation from a string", async ({ expect }) => {
    const userDid = await userSigner.getDid();
    const serviceDid = await serviceSigner.getDid();

    const rootDelegationString = await Builder.delegation()
      .audience(userDid)
      .subject(userDid)
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
    expect(decoded.nuc.payload.iss.didString).toBe(userDid.didString);
    expect(Payload.isInvocationPayload(decoded.nuc.payload)).toBe(true);
    if (Payload.isInvocationPayload(decoded.nuc.payload)) {
      expect(decoded.nuc.payload.args).toEqual({ foo: "bar" });
    }
  });
});
