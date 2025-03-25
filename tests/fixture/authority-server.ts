import { StargateClient } from "@cosmjs/stargate";
import { secp256k1 } from "@noble/curves/secp256k1";
import { http, HttpResponse } from "msw";
import { type SetupServerApi, setupServer } from "msw/node";
import { Temporal } from "temporal-polyfill";
import { NucTokenBuilder } from "#/builder";
import type { Keypair } from "#/keypair";
import { Command, Did } from "#/token";
import { Env } from "./env";

export class AuthorityServer {
  readonly baseUrl: string = "http://authority-service.com";
  private server?: SetupServerApi;

  constructor(public readonly keyPair: Keypair) {}

  private readonly handlers = [
    http.get(`${this.baseUrl}/about`, () => {
      return HttpResponse.json({
        public_key: this.keyPair.publicKey("hex"),
      });
    }),

    http.post(`${this.baseUrl}/api/v1/nucs/create`, async ({ request }) => {
      const data = (await request.json()) as Record<string, string>;

      secp256k1.verify(data.signature, data.payload, data.public_key, {
        prehash: true,
      });

      const payload = JSON.parse(
        Buffer.from(data.payload, "hex").toString(),
      ) as Record<string, unknown>;

      if (payload.target_public_key !== this.keyPair.publicKey("hex")) {
        throw new Error("unknown target");
      }

      const token = NucTokenBuilder.delegation([])
        .command(new Command(["nil"]))
        .subject(Did.fromHex(data.public_key))
        .audience(Did.fromHex(data.public_key))
        .expiresAt(
          Temporal.Instant.fromEpochSeconds(payload.expires_at as number),
        )
        .build(this.keyPair.privateKey());

      return HttpResponse.json({ token });
    }),

    http.post(
      `${this.baseUrl}/api/v1/payments/validate`,
      async ({ request }) => {
        const data = (await request.json()) as Record<string, unknown>;
        const client = await StargateClient.connect(Env.nilChainUrl);
        const result = await client.getTx(data.tx_hash as string);
        const payload = data.payload as Record<string, string>;
        if (!this.keyPair.matchesPublicKey(payload.service_public_key)) {
          throw new Error("unknown service");
        }
        if (!result) {
          throw Error("transaction not found.");
        }
        return HttpResponse.json({});
      },
    ),
  ];

  init() {
    this.server = setupServer(...this.handlers);
    this.server.listen();
  }

  close() {
    if (this.server) {
      this.server.close();
    }
  }

  resetHandlers() {
    if (this.server) {
      this.server.resetHandlers();
    }
  }
}
