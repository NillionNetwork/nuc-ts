import { bytesToHex } from "@noble/hashes/utils";
import { beforeAll, describe, expect, it } from "vitest";
import * as did from "#/core/did/did";
import { Keypair } from "#/core/keypair";
import type { Envelope } from "#/nuc/envelope";
import { computeHash } from "#/nuc/envelope";
import { NilauthClient } from "#/services/nilauth/client";
import { PayerBuilder } from "#/services/payer/builder";

const Env = {
  nilAuthUrl: process.env.NILLION_NILAUTH_URL ?? "",
  nilChainUrl: process.env.NILLION_NILCHAIN_JSON_RPC ?? "",
  NilauthClient: process.env.NILLION_NILCHAIN_PRIVATE_KEY_0 ?? "",
};

describe("nilauth client", () => {
  const keypair = Keypair.from(Env.NilauthClient);
  let nilauthClient: NilauthClient;

  beforeAll(async () => {
    const payer = await PayerBuilder.fromKeypair(keypair)
      .chainUrl(Env.nilChainUrl)
      .build();
    nilauthClient = await NilauthClient.create(Env.nilAuthUrl, payer);
  });

  it("fetch subscription cost", async () => {
    const response = await nilauthClient.subscriptionCost("nildb");
    expect(response).toBe(1000000);
  });

  it("is not subscribed", async () => {
    const response = await nilauthClient.subscriptionStatus(
      keypair.publicKey(),
      "nildb",
    );
    expect(response.subscribed).toBeFalsy();
  });

  it("pay and validate subscription", async () => {
    const promise = nilauthClient.payAndValidate(keypair.publicKey(), "nildb");
    await expect(promise).resolves.toBeUndefined();
  });

  it("is subscribed", async () => {
    const response = await nilauthClient.subscriptionStatus(
      keypair.publicKey(),
      "nildb",
    );
    expect(response.subscribed).toBeTruthy();
  });

  let envelope: Envelope;
  it("request token", async () => {
    const parsedDid = keypair.toDid("nil");
    const nowInSeconds = Math.floor(Date.now() / 1000);

    const response = await nilauthClient.requestToken(keypair, "nildb");
    envelope = response.token;

    expect(did.areEqual(envelope.nuc.payload.sub, parsedDid)).toBeTruthy();
    expect(did.areEqual(envelope.nuc.payload.aud, parsedDid)).toBeTruthy();
    expect(envelope.nuc.payload.cmd).toStrictEqual("/nil/db");
    expect(envelope.nuc.payload.exp).toBeGreaterThan(nowInSeconds);

    const tokenHash = bytesToHex(computeHash(envelope.nuc));
    const { revoked } =
      await nilauthClient.findRevocationsInProofChain(envelope);
    const wasRevoked = revoked.some((t) => t.tokenHash === tokenHash);
    expect(wasRevoked).toBeFalsy();
  });

  it("revoke token", async () => {
    const { token: authToken } = await nilauthClient.requestToken(
      keypair,
      "nildb",
    );

    await nilauthClient.revokeToken({
      keypair,
      authToken,
      tokenToRevoke: envelope,
    });

    await new Promise((f) => setTimeout(f, 200));

    const tokenHash = bytesToHex(computeHash(envelope.nuc));
    const { revoked } =
      await nilauthClient.findRevocationsInProofChain(envelope);
    const wasRevoked = revoked.some((t) => t.tokenHash === tokenHash);
    expect(wasRevoked).toBeTruthy();
  });
});
