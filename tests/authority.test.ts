import { Temporal } from "temporal-polyfill";
import { describe } from "vitest";
import { Command, Did } from "#/token";
import { Env } from "./fixture/env";
import { createTestFixtureExtension } from "./fixture/it";
import { Keypair } from "#/keypair";

describe("authority service", () => {
  const { it, beforeAll, afterAll, afterEach } = createTestFixtureExtension(
    Env.AuthorityService,
  );

  beforeAll(async () => {});

  afterAll(async () => {});

  afterEach(async () => {});

  it("about", async ({ expect, authorityService, authorityServer }) => {
    const aboutInfo = await authorityService.about();
    expect(aboutInfo.publicKey).toBe(authorityServer.keyPair.publicKey("hex"));
  });

  it("request token", async ({ expect, authorityService }) => {
    const keypair = Keypair.generate();
    const did = new Did(keypair.publicKey());
    const now = Temporal.Now.instant().epochSeconds;

    const envelope = (await authorityService.requestToken(keypair.privateKey()))
      .token;

    envelope.validateSignatures();

    expect(envelope.token.token.subject.isEqual(did)).toBeTruthy();
    expect(envelope.token.token.audience.isEqual(did)).toBeTruthy();
    expect(envelope.token.token.command).toStrictEqual(new Command(["nil"]));
    expect(envelope.token.token.expiresAt?.epochSeconds).toBeGreaterThan(now);
  });

  it("pay subscription", async ({
    expect,
    authorityService,
    keypair,
    payer,
  }) => {
    const response = await authorityService.paySubscription(
      keypair.publicKey(),
      payer,
    );
    expect(response).toBeTruthy();
  });
});
