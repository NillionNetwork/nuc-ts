import { Temporal } from "temporal-polyfill";
import { describe } from "vitest";
import { Command, Did } from "#/token";
import { Env } from "./fixture/env";
import { createTestFixtureExtension } from "./fixture/it";
import { startTokenPriceService } from "./fixture/price-service";

describe("nilauth client", () => {
  const { it, beforeAll } = createTestFixtureExtension(Env.NilauthClient);

  beforeAll(async () => {
    startTokenPriceService();
  });

  it("about", async ({ expect, nilauthClient }) => {
    const now = Temporal.Now.instant();
    const aboutInfo = await nilauthClient.about();
    expect(aboutInfo.started.epochSeconds).toBeLessThan(now.epochSeconds);
    expect(aboutInfo.publicKey).toBe(
      "03520e70bd97a5fa6d70c614d50ee47bf445ae0b0941a1d61ddd5afa022b97ab14",
    );
    expect(aboutInfo.build.timestamp.epochSeconds).toBeLessThan(
      now.epochSeconds,
    );
    expect(aboutInfo.build.commit).toBeDefined();
  });

  it("fetch subscription cost", async ({ expect, nilauthClient }) => {
    const response = await nilauthClient.subscriptionCost();
    expect(response).toBe(1000000);
  });

  it("pay subscription", async ({ expect, nilauthClient, keypair, payer }) => {
    const response = await nilauthClient.paySubscription(
      keypair.publicKey("hex"),
      payer,
    );
    expect(response).toBeNull();
  });

  it("request token", async ({ expect, nilauthClient, keypair }) => {
    const did = new Did(keypair.publicKey("bytes"));
    const now = Temporal.Now.instant().epochSeconds;

    const envelope = (
      await nilauthClient.requestToken(keypair.privateKey("bytes"))
    ).token;

    envelope.validateSignatures();

    expect(envelope.token.token.subject.isEqual(did)).toBeTruthy();
    expect(envelope.token.token.audience.isEqual(did)).toBeTruthy();
    expect(envelope.token.token.command).toStrictEqual(new Command(["nil"]));
    expect(envelope.token.token.expiresAt?.epochSeconds).toBeGreaterThan(now);
  });
});
