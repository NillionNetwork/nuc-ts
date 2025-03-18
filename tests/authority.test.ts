import { secp256k1 } from "@noble/curves/secp256k1";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { Temporal } from "temporal-polyfill";
import { afterAll, afterEach, beforeAll, describe, it } from "vitest";
import { AuthorityService } from "#/authority";
import { NucTokenBuilder } from "#/builder";
import { Command, Did } from "#/token";

const BASE_URL = "http://authority-service.com";
const PRIVATE_KEY = secp256k1.utils.randomPrivateKey();
const PUBLIC_KEY = Buffer.from(secp256k1.getPublicKey(PRIVATE_KEY)).toString(
  "hex",
);

const handlers = [
  http.get(`${BASE_URL}/about`, () => {
    return HttpResponse.json({
      public_key: PUBLIC_KEY,
    });
  }),
  http.post(`${BASE_URL}/api/v1/nucs/create`, async ({ request }) => {
    const data = (await request.json()) as Record<string, string>;

    secp256k1.verify(data.signature, data.payload, data.public_key, {
      prehash: true,
    });

    const payload = JSON.parse(
      Buffer.from(data.payload, "hex").toString(),
    ) as Record<string, unknown>;

    if (payload.target_public_key !== PUBLIC_KEY) {
      throw new Error("unknown target");
    }

    const token = NucTokenBuilder.delegation([])
      .command(new Command(["nil"]))
      .subject(Did.fromHex(data.public_key))
      .audience(Did.fromHex(data.public_key))
      .expiresAt(
        Temporal.Instant.fromEpochSeconds(payload.expires_at as number),
      )
      .build(PRIVATE_KEY);

    return HttpResponse.json({ token });
  }),
];
const server = setupServer(...handlers);

describe("authority service", () => {
  const service = new AuthorityService(BASE_URL);

  beforeAll(async () => {
    server.listen();
  });

  afterAll(async () => server.close());

  afterEach(async () => server.resetHandlers());

  it("about", async ({ expect }) => {
    const aboutInfo = await service.about();
    expect(aboutInfo.publicKey).toBe(PUBLIC_KEY);
  });

  it("request token", async ({ expect }) => {
    const privateKey = secp256k1.utils.randomPrivateKey();
    const publicKey = secp256k1.getPublicKey(privateKey);
    const did = new Did(publicKey);
    const now = Temporal.Now.instant().epochSeconds;

    const envelope = (await service.requestToken(privateKey)).token;

    envelope.validateSignatures();

    expect(envelope.token.token.subject.compare(did)).toBe(0);
    expect(envelope.token.token.audience.compare(did)).toBe(0);
    expect(envelope.token.token.command).toStrictEqual(new Command(["nil"]));
    expect(envelope.token.token.expiresAt?.epochSeconds).toBeGreaterThan(now);
  });
});
