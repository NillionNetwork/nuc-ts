import { secp256k1 } from "@noble/curves/secp256k1";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { afterAll, afterEach, beforeAll, describe, it } from "vitest";
import { AuthorityService } from "#/authority";
import { NucTokenBuilder } from "#/builder";
import { Command, Did } from "#/token";

const BASE_URL = "http://authority-service.com";
const PUBLIC_KEY =
  "03520e70bd97a5fa6d70c614d50ee47bf445ae0b0941a1d61ddd5afa022b97ab14";

const handlers = [
  http.get(`${BASE_URL}/about`, () => {
    return HttpResponse.json({
      public_key: PUBLIC_KEY,
    });
  }),
  http.post(`${BASE_URL}/api/v1/nucs/create`, async ({ request }) => {
    const data = (await request.json()) as Record<string, string>;
    const privateKey = secp256k1.utils.randomPrivateKey();

    const publicKey = data.public_key as string;

    secp256k1.verify(data.signature, data.payload, publicKey, {
      prehash: true,
    });

    const token = NucTokenBuilder.delegation([])
      .command(new Command(["nil"]))
      .subject(Did.fromHex(publicKey))
      .audience(Did.fromHex(publicKey))
      .build(privateKey);

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
    const envelope = (await service.requestToken(privateKey)).token;

    envelope.validateSignatures();

    expect(envelope.token.token.subject.compare(did)).toBe(0);
    expect(envelope.token.token.audience.compare(did)).toBe(0);
    expect(envelope.token.token.command).toStrictEqual(new Command(["nil"]));
  });
});
