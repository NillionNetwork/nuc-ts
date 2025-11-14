import { describe, it } from "vitest";
import { FOUR_WEEKS_MS, ONE_HOUR_MS } from "#/constants";
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
      .expiresIn(ONE_HOUR_MS)
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
      .expiresIn(ONE_HOUR_MS)
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
      .expiresIn(ONE_HOUR_MS)
      .sign(rootSigner);

    const chainedEnvelope = await Builder.delegationFrom(rootEnvelope)
      .audience(aud) // new audience
      .expiresIn(ONE_HOUR_MS / 2)
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
      .expiresIn(ONE_HOUR_MS)
      .sign(rootSigner);

    // Create an invocation from the delegation
    const invocationEnvelope = await Builder.invocationFrom(delegationEnvelope)
      .audience(aud) // new audience
      .addArgument("action", "read")
      .addArgument("resourceId", 456)
      .expiresIn(ONE_HOUR_MS / 2)
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
      .expiresIn(ONE_HOUR_MS)
      .signAndSerialize(rootSigner);

    expect(typeof serializedToken).toBe("string");
    const decoded = Codec._unsafeDecodeBase64Url(serializedToken);
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
      .expiresIn(ONE_HOUR_MS)
      .signAndSerialize(rootSigner);

    const chainedDelegationString = await Builder.delegationFromString(
      rootDelegationString,
    )
      .audience(serviceDid)
      .expiresIn(ONE_HOUR_MS / 2)
      .signAndSerialize(userSigner);

    const decoded = Codec._unsafeDecodeBase64Url(chainedDelegationString);
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
      .expiresIn(ONE_HOUR_MS)
      .signAndSerialize(rootSigner);

    const invocationString = await Builder.invocationFromString(
      rootDelegationString,
    )
      .audience(serviceDid)
      .arguments({ foo: "bar" })
      .expiresIn(ONE_HOUR_MS / 2)
      .signAndSerialize(userSigner);

    const decoded = Codec._unsafeDecodeBase64Url(invocationString);
    expect(decoded.proofs).toHaveLength(1);
    expect(decoded.nuc.payload.iss.didString).toBe(userDid.didString);
    expect(Payload.isInvocationPayload(decoded.nuc.payload)).toBe(true);
    if (Payload.isInvocationPayload(decoded.nuc.payload)) {
      expect(decoded.nuc.payload.args).toEqual({ foo: "bar" });
    }
  });
});

describe("Builder Expiration and Lifetime", () => {
  const signer = Signer.generate();
  const aud = Signer.generate();
  const sub = Signer.generate();

  it("should throw an error if expiration is not set", async ({ expect }) => {
    const audDid = await aud.getDid();
    const subDid = await sub.getDid();

    const builder = Builder.delegation()
      .audience(audDid)
      .subject(subDid)
      .command("/test");

    await expect(builder.sign(signer)).rejects.toThrow(
      "Expiration is a required field.",
    );
  });

  it("should throw an error if expiration is in the past", async ({
    expect,
  }) => {
    const audDid = await aud.getDid();
    const subDid = await sub.getDid();

    const builder = Builder.delegation()
      .audience(audDid)
      .subject(subDid)
      .command("/test")
      .expiresAt(Date.now() - 1000);

    await expect(builder.sign(signer)).rejects.toThrow(
      "Expiration date must be in the future.",
    );
  });

  it("should correctly set expiration using expiresIn", async ({ expect }) => {
    const audDid = await aud.getDid();
    const subDid = await sub.getDid();
    const now = Date.now();
    const lifetime = 5 * 60 * 1000; // 5 minutes

    const envelope = await Builder.delegation()
      .audience(audDid)
      .subject(subDid)
      .command("/test")
      .expiresIn(lifetime)
      .sign(signer);

    const expectedExp = Math.floor((now + lifetime) / 1000);
    // Allow for a 1-second clock skew during test run
    expect(envelope.nuc.payload.exp).toBeGreaterThanOrEqual(expectedExp - 1);
    expect(envelope.nuc.payload.exp).toBeLessThanOrEqual(expectedExp + 1);
  });

  it("should throw if expiration exceeds the default max lifetime", async ({
    expect,
  }) => {
    const audDid = await aud.getDid();
    const subDid = await sub.getDid();
    const longLifetime = FOUR_WEEKS_MS + 1000;

    const builder = Builder.delegation()
      .audience(audDid)
      .subject(subDid)
      .command("/test")
      .expiresIn(longLifetime);

    await expect(builder.sign(signer)).rejects.toThrow(
      "exceeds the maximum lifetime",
    );
  });

  it("should allow setting a shorter max lifetime", async ({ expect }) => {
    const audDid = await aud.getDid();
    const subDid = await sub.getDid();
    const shortMaxLifetime = 60 * 1000; // 1 minute

    // This should succeed
    const envelope = await Builder.delegation()
      .audience(audDid)
      .subject(subDid)
      .command("/test")
      .maxLifetime(shortMaxLifetime)
      .expiresIn(shortMaxLifetime - 1)
      .sign(signer);
    expect(envelope).toBeDefined();

    // This should fail
    const builder = Builder.delegation()
      .audience(audDid)
      .subject(subDid)
      .command("/test")
      .maxLifetime(shortMaxLifetime)
      .expiresIn(shortMaxLifetime + 1);

    await expect(builder.sign(signer)).rejects.toThrow(
      "exceeds the maximum lifetime. Max expiry is",
    );
  });

  it("should throw when trying to set a max lifetime longer than allowed", async ({
    expect,
  }) => {
    const audDid = await aud.getDid();
    const subDid = await sub.getDid();
    const builder = Builder.delegation()
      .audience(audDid)
      .subject(subDid)
      .command("/test");

    expect(() => builder.maxLifetime(FOUR_WEEKS_MS + 1000)).toThrow(
      "exceeds the allowed maximum",
    );
  });

  it("should cap a chained token's lifetime by its parent's", async ({
    expect,
  }) => {
    const userSigner = Signer.generate();
    const userDid = await userSigner.getDid();
    const serviceDid = await Signer.generate().getDid();
    const rootSigner = Signer.generate();

    const parentLifetime = 5 * 60 * 1000; // 5 minutes

    const rootDelegation = await Builder.delegation()
      .audience(userDid)
      .subject(userDid)
      .command("/test")
      .expiresIn(parentLifetime)
      .sign(rootSigner);

    // This should fail because child tries to live longer than parent's remaining life
    const childBuilder = Builder.delegationFrom(rootDelegation)
      .audience(serviceDid)
      .expiresIn(parentLifetime + 1000);

    await expect(childBuilder.sign(userSigner)).rejects.toThrow(
      "exceeds the maximum lifetime",
    );

    // This should succeed
    const validChild = await Builder.delegationFrom(rootDelegation)
      .audience(serviceDid)
      .expiresIn(parentLifetime / 2)
      .sign(userSigner);
    expect(validChild).toBeDefined();
  });

  it("should correctly convert ms to seconds in payload for exp and nbf", async ({
    expect,
  }) => {
    const audDid = await aud.getDid();
    const subDid = await sub.getDid();
    const now = Date.now();

    const envelope = await Builder.delegation()
      .audience(audDid)
      .subject(subDid)
      .command("/test")
      .notBefore(now - 10000)
      .expiresAt(now + ONE_HOUR_MS)
      .sign(signer);

    const payload = envelope.nuc.payload;
    expect(payload.nbf).toBe(Math.floor((now - 10000) / 1000));
    expect(payload.exp).toBe(Math.floor((now + ONE_HOUR_MS) / 1000));
  });
});
