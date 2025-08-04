import { bytesToHex } from "@noble/hashes/utils";
import { beforeAll, describe, expect, it } from "vitest";
import { Did } from "#/core/did/did";
import { Keypair } from "#/core/keypair";
import { Signer } from "#/core/signer";
import { Builder } from "#/nuc/builder";
import { Envelope } from "#/nuc/envelope";
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
    nilauthClient = await NilauthClient.create({
      baseUrl: Env.nilAuthUrl,
      payer,
    });
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

    expect(Did.areEqual(envelope.nuc.payload.sub, parsedDid)).toBeTruthy();
    expect(Did.areEqual(envelope.nuc.payload.aud, parsedDid)).toBeTruthy();
    expect(envelope.nuc.payload.cmd).toStrictEqual("/nil/db");
    expect(envelope.nuc.payload.exp).toBeGreaterThan(nowInSeconds);

    const tokenHash = bytesToHex(Envelope.computeHash(envelope.nuc));
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

    const tokenHash = bytesToHex(Envelope.computeHash(envelope.nuc));
    const { revoked } =
      await nilauthClient.findRevocationsInProofChain(envelope);
    const wasRevoked = revoked.some((t) => t.tokenHash === tokenHash);
    expect(wasRevoked).toBeTruthy();
  });
});

describe("NilauthClient without a Payer", () => {
  let clientWithoutPayer: NilauthClient;

  beforeAll(async () => {
    clientWithoutPayer = await NilauthClient.create({
      baseUrl: Env.nilAuthUrl,
    });
  });

  it("should successfully perform read-only operations", async () => {
    // Create a dummy token to check for revocation
    const testKeypair = Keypair.generate();
    const tokenToRevoke = await Builder.delegation()
      .audience(testKeypair.toDid())
      .subject(testKeypair.toDid())
      .command("/test")
      .build(Signer.fromKeypair(Keypair.generate()));

    // This should succeed as it doesn't require a payer
    const promise =
      clientWithoutPayer.findRevocationsInProofChain(tokenToRevoke);
    await expect(promise).resolves.not.toThrow();
  });

  it("should throw when performing a write operation", async () => {
    const promise = clientWithoutPayer.payAndValidate(
      "some-public-key",
      "nildb",
    );
    await expect(promise).rejects.toThrow(
      "A Payer instance is required for this operation.",
    );
  });
});
