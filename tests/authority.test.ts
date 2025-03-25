import { secp256k1 } from "@noble/curves/secp256k1";
import { Temporal } from "temporal-polyfill";
import { describe } from "vitest";
import { Command, Did } from "#/token";
import { Env } from "./fixture/env";
import { createTestFixtureExtension } from "./fixture/it";

describe("authority service", () => {
  const { it, beforeAll, afterAll, afterEach } = createTestFixtureExtension(
    Env.AuthorityService,
  );

  beforeAll(async () => {});

  afterAll(async () => {});

  afterEach(async () => {});

  it("about", async ({ expect, authorityService, authorityServer }) => {
    const aboutInfo = await authorityService.about();
    expect(aboutInfo.publicKey).toBe(authorityServer.keyPair.publicKey);
  });

  it("request token", async ({ expect, authorityService }) => {
    const privateKey = secp256k1.utils.randomPrivateKey();
    const publicKey = secp256k1.getPublicKey(privateKey);
    const did = new Did(publicKey);
    const now = Temporal.Now.instant().epochSeconds;

    const envelope = (await authorityService.requestToken(privateKey)).token;

    envelope.validateSignatures();

    expect(envelope.token.token.subject.isEqual(did)).toBeTruthy();
    expect(envelope.token.token.audience.isEqual(did)).toBeTruthy();
    expect(envelope.token.token.command).toStrictEqual(new Command(["nil"]));
    expect(envelope.token.token.expiresAt?.epochSeconds).toBeGreaterThan(now);
  });

  it("pay subscription", async ({
    expect,
    authorityService,
    signer,
    payer,
  }) => {
    const response = await authorityService.paySubscription(
      signer.publicKeyAsBytes(),
      payer,
    );
    expect(response).toBeTruthy();
  });
});
