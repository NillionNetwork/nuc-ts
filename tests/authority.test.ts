import { Temporal } from "temporal-polyfill";
import { describe } from "vitest";
import { Command, Did } from "#/token";
import { Env } from "./fixture/env";
import { createTestFixtureExtension } from "./fixture/it";

describe("authority service", () => {
  const { it, beforeAll } = createTestFixtureExtension(Env.AuthorityService);

  beforeAll(async () => {});

  it("about", async ({ expect, authorityService }) => {
    const aboutInfo = await authorityService.about();
    expect(aboutInfo.publicKey).toBe(
      "03520e70bd97a5fa6d70c614d50ee47bf445ae0b0941a1d61ddd5afa022b97ab14",
    );
  });

  it("pay subscription", async ({
    expect,
    authorityService,
    keypair,
    payer,
  }) => {
    const response = await authorityService.paySubscription(
      keypair.publicKey("hex"),
      payer,
    );
    expect(response).toBeNull();
  });

  it("request token", async ({ expect, authorityService, keypair }) => {
    const did = new Did(keypair.publicKey("bytes"));
    const now = Temporal.Now.instant().epochSeconds;

    const envelope = (
      await authorityService.requestToken(keypair.privateKey("bytes"))
    ).token;

    envelope.validateSignatures();

    expect(envelope.token.token.subject.isEqual(did)).toBeTruthy();
    expect(envelope.token.token.audience.isEqual(did)).toBeTruthy();
    expect(envelope.token.token.command).toStrictEqual(new Command(["nil"]));
    expect(envelope.token.token.expiresAt?.epochSeconds).toBeGreaterThan(now);
  });
});
