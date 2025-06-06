import { bytesToHex } from "@noble/hashes/utils";
import { Temporal } from "temporal-polyfill";
import { describe } from "vitest";
import type { NucTokenEnvelope } from "#/envelope";
import { Command, Did } from "#/token";
import { Env } from "./fixture/env";
import { createTestFixtureExtension } from "./fixture/it";

describe("nilauth client", () => {
  const { it, beforeAll } = createTestFixtureExtension(Env.NilauthClient);

  beforeAll(async () => {});

  it("health", async ({ expect, nilauthClient }) => {
    const response = await nilauthClient.health();
    expect(response).toBe("OK");
  });

  it("about", async ({ expect, nilauthClient }) => {
    const now = Temporal.Now.instant();
    const aboutInfo = await nilauthClient.about();
    expect(aboutInfo.started.epochMilliseconds).toBeLessThan(
      now.epochMilliseconds,
    );
    expect(aboutInfo.publicKey).toBe(
      "03520e70bd97a5fa6d70c614d50ee47bf445ae0b0941a1d61ddd5afa022b97ab14",
    );
    expect(aboutInfo.build.timestamp.epochMilliseconds).toBeLessThanOrEqual(
      now.epochMilliseconds,
    );
    expect(aboutInfo.build.commit).toBeDefined();
  });

  it("fetch subscription cost", async ({ expect, nilauthClient }) => {
    const response = await nilauthClient.subscriptionCost("nildb");
    expect(response).toBe(1000000);
  });

  it("is not subscribed", async ({ expect, nilauthClient }) => {
    const response = await nilauthClient.subscriptionStatus(
      nilauthClient.keypair.publicKey("hex"),
      "nildb",
    );
    expect(response.subscribed).toBeFalsy();
  });

  it("pay and validate subscription", async ({ expect, nilauthClient }) => {
    const result = await nilauthClient.payAndValidate("nildb");
    expect(result).toBeUndefined();
  });

  it("is subscribed", async ({ expect, nilauthClient }) => {
    const response = await nilauthClient.subscriptionStatus(
      nilauthClient.keypair.publicKey("hex"),
      "nildb",
    );
    expect(response.subscribed).toBeTruthy();
  });

  it("cannot renew subscription yet", async ({ expect, nilauthClient }) => {
    const promise = nilauthClient.payAndValidate("nildb");
    await expect(promise).rejects.toThrow("cannot renew subscription yet");
  });

  let envelope: NucTokenEnvelope;
  it("request token", async ({ expect, nilauthClient }) => {
    const did = new Did(nilauthClient.keypair.publicKey());
    const now = Temporal.Now.instant().epochMilliseconds;

    envelope = (await nilauthClient.requestToken("nildb")).token;

    envelope.validateSignatures();

    expect(envelope.token.token.subject.isEqual(did)).toBeTruthy();
    expect(envelope.token.token.audience.isEqual(did)).toBeTruthy();
    expect(envelope.token.token.command).toStrictEqual(
      new Command(["nil", "db"]),
    );
    expect(envelope.token.token.expiresAt?.epochMilliseconds).toBeGreaterThan(
      now,
    );

    await new Promise((f) => setTimeout(f, 200));
    const computeHash = bytesToHex(envelope.token.computeHash());

    const { revoked } =
      await nilauthClient.findRevocationsInProofChain(envelope);

    const wasRevoked = revoked.map((t) => t.tokenHash).includes(computeHash);
    expect(wasRevoked).toBeFalsy();
  });

  it("revoke token", async ({ expect, nilauthClient }) => {
    const authToken = await nilauthClient.requestToken("nildb");
    await nilauthClient.revokeToken(authToken.token, envelope);

    await new Promise((f) => setTimeout(f, 200));
    const computeHash = bytesToHex(envelope.token.computeHash());
    const { revoked } =
      await nilauthClient.findRevocationsInProofChain(envelope);

    const wasRevoked = revoked.map((t) => t.tokenHash).includes(computeHash);
    expect(wasRevoked).toBeTruthy();
  });
});
