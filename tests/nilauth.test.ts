import { bytesToHex } from "@noble/hashes/utils";
import { Temporal } from "temporal-polyfill";
import { describe } from "vitest";
import type { NucTokenEnvelope } from "#/envelope";
import { Command, Did } from "#/token";
import { Env } from "./fixture/env";
import { createTestFixtureExtension } from "./fixture/it";
import { startTokenPriceService } from "./fixture/price-service";

describe("nilauth client", () => {
  const { it, beforeAll } = createTestFixtureExtension(Env.NilauthClient);

  beforeAll(async () => {
    startTokenPriceService();
  });

  it("health", async ({ expect, nilauthClient }) => {
    const response = await nilauthClient.health();
    expect(response).toBe("OK");
  });

  it("about", async ({ expect, nilauthClient }) => {
    const now = Temporal.Now.instant();
    const aboutInfo = await nilauthClient.about();
    expect(aboutInfo.started.epochSeconds).toBeLessThan(now.epochSeconds);
    expect(aboutInfo.publicKey).toBe(
      "03520e70bd97a5fa6d70c614d50ee47bf445ae0b0941a1d61ddd5afa022b97ab14",
    );
    expect(aboutInfo.build.timestamp.epochSeconds).toBeLessThanOrEqual(
      now.epochSeconds,
    );
    expect(aboutInfo.build.commit).toBeDefined();
  });

  it("fetch subscription cost", async ({ expect, nilauthClient }) => {
    const response = await nilauthClient.subscriptionCost();
    expect(response).toBe(1000000);
  });

  it("pay subscription", async ({ nilauthClient, keypair, payer }) => {
    await nilauthClient.paySubscription(keypair.publicKey("hex"), payer);
  });

  let envelope: NucTokenEnvelope;
  it("request token", async ({ expect, nilauthClient, keypair }) => {
    const did = new Did(keypair.publicKey("bytes"));
    const now = Temporal.Now.instant().epochSeconds;

    envelope = (await nilauthClient.requestToken(keypair)).token;

    envelope.validateSignatures();

    expect(envelope.token.token.subject.isEqual(did)).toBeTruthy();
    expect(envelope.token.token.audience.isEqual(did)).toBeTruthy();
    expect(envelope.token.token.command).toStrictEqual(new Command(["nil"]));
    expect(envelope.token.token.expiresAt?.epochSeconds).toBeGreaterThan(now);

    await new Promise((f) => setTimeout(f, 200));
    const computeHash = bytesToHex(envelope.token.computeHash());
    const revokedToken = await nilauthClient.lookupRevokedTokens(envelope);
    expect(
      revokedToken.revoked.map((t) => t.tokenHash).includes(computeHash),
    ).toBeFalsy();
  });

  it("revoke token", async ({ expect, nilauthClient, keypair }) => {
    await nilauthClient.revokeToken(keypair, envelope);

    await new Promise((f) => setTimeout(f, 200));
    const computeHash = bytesToHex(envelope.token.computeHash());
    const revokedToken = await nilauthClient.lookupRevokedTokens(envelope);
    expect(
      revokedToken.revoked.map((t) => t.tokenHash).includes(computeHash),
    ).toBeTruthy();
  });
});
