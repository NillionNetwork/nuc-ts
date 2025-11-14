import { bytesToHex } from "@noble/hashes/utils.js";
import { beforeAll, describe, expect, it } from "vitest";
import { ONE_HOUR_MS } from "#/constants";
import { Did } from "#/core/did/did";
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
  const signer = Signer.fromPrivateKey(Env.NilauthClient);
  let nilauthClient: NilauthClient;

  beforeAll(async () => {
    const payer = await PayerBuilder.fromPrivateKey(Env.NilauthClient)
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
      await signer.getDid(),
      "nildb",
    );
    expect(response.subscribed).toBeFalsy();
  });

  it("pay and validate subscription", async () => {
    const promise = nilauthClient.payAndValidate(
      signer,
      await signer.getDid(),
      "nildb",
    );
    await expect(promise).resolves.toBeUndefined();
  });

  it("is subscribed", async () => {
    const response = await nilauthClient.subscriptionStatus(
      await signer.getDid(),
      "nildb",
    );
    expect(response.subscribed).toBeTruthy();
  });

  let envelope: Envelope;
  it("request token", async () => {
    const parsedDid = await signer.getDid();
    const nowInSeconds = Math.floor(Date.now() / 1000);

    const response = await nilauthClient.requestToken(signer, "nildb");
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

  it("should revoke intermediate delegation", async () => {
    // Phase 1: Build a 3-part delegation chain
    // 1. Get a root token from nilauth
    const { token: rootToken } = await nilauthClient.requestToken(
      signer, // The root signer for the test suite
      "nildb",
    );

    // 2. Delegate root token to a user.
    const userSigner = Signer.generate();
    const userDid = await userSigner.getDid();

    // Calculate parent's remaining lifetime and use a fraction of it
    const parentExp = rootToken.nuc.payload.exp;
    const remainingLifetimeMs = (parentExp as number) * 1000 - Date.now();

    const userDelegation = await Builder.delegationFrom(rootToken)
      .audience(userDid)
      .subject(userDid)
      .command("/some/specific/capability")
      .expiresIn(remainingLifetimeMs * 0.8)
      .sign(signer);

    // 3. The user invokes their delegation.
    const finalInvocation = await Builder.invocationFrom(userDelegation)
      .audience(await Signer.generate().getDid()) // Some final service
      .expiresIn(remainingLifetimeMs * 0.5)
      .sign(userSigner); // Signed by the user

    // Phase 2: Revoke the intermediate token (userDelegation)
    // 1. Get a fresh authToken to authorize the revocation itself.
    const { token: authToken } = await nilauthClient.requestToken(
      signer,
      "nildb",
    );

    // 2. Root revokes the delegation (userDelegation)
    await nilauthClient.revokeToken({
      signer: signer,
      authToken,
      tokenToRevoke: userDelegation,
    });
    await new Promise((resolve) => setTimeout(resolve, 200));

    // Phase 3: Verify the revocation status from the final token
    const revokedTokenHash = bytesToHex(
      Envelope.computeHash(userDelegation.nuc),
    );

    // 1. Ask the service: are any of its proofs revoked?"
    const { revoked } =
      await nilauthClient.findRevocationsInProofChain(finalInvocation);

    // 2. Assert that the service correctly identified the revoked middle link.
    const wasRevoked = revoked.some((t) => t.tokenHash === revokedTokenHash);
    expect(wasRevoked).toBe(true);

    // Also assert that the root token itself was not part of the revoked list.
    const rootTokenHash = bytesToHex(Envelope.computeHash(rootToken.nuc));
    const wasRootRevoked = revoked.some((t) => t.tokenHash === rootTokenHash);
    expect(wasRootRevoked).toBe(false);
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
    const testSigner = Signer.generate();
    const testDid = await testSigner.getDid();
    const tokenToRevoke = await Builder.delegation()
      .audience(testDid)
      .subject(testDid)
      .command("/test")
      .expiresIn(ONE_HOUR_MS)
      .sign(Signer.generate());

    // This should succeed as it doesn't require a payer
    const promise =
      clientWithoutPayer.findRevocationsInProofChain(tokenToRevoke);
    await expect(promise).resolves.not.toThrow();
  });

  it("should throw when performing a write operation", async () => {
    const testSigner = Signer.generate();
    const promise = clientWithoutPayer.payAndValidate(
      testSigner,
      await testSigner.getDid(),
      "nildb",
    );
    await expect(promise).rejects.toThrow(
      "A Payer instance is required for this operation.",
    );
  });
});

describe("nilauth client - decoupled payment flow", () => {
  let nilauthClient: NilauthClient;

  beforeAll(async () => {
    const payer = await PayerBuilder.fromPrivateKey(Env.NilauthClient)
      .chainUrl(Env.nilChainUrl)
      .build();
    nilauthClient = await NilauthClient.create({
      baseUrl: Env.nilAuthUrl,
      payer,
    });
  });

  it("should successfully pay and validate a subscription using the decoupled flow", async () => {
    const payerSigner = Signer.fromPrivateKey(Env.NilauthClient);
    const subscriberSigner = Signer.generate();
    const payerDid = await payerSigner.getDid();
    const subscriberDid = await subscriberSigner.getDid();
    const blindModule = "nilai";

    // 1. Check current status (should not be subscribed)
    const initialStatus = await nilauthClient.subscriptionStatus(
      subscriberDid,
      blindModule,
    );
    expect(initialStatus.subscribed).toBeFalsy();

    // 2. Get subscription cost
    const costUnil = await nilauthClient.subscriptionCost(blindModule);
    expect(costUnil).toBeGreaterThan(0);

    // 3. Create payment resource
    const { resourceHash, payload } = nilauthClient.createPaymentResource(
      subscriberDid,
      blindModule,
      payerDid,
    );

    // 4. Pay on-chain
    const txHash = await nilauthClient.payer?.pay(resourceHash, costUnil);
    expect(txHash).toBeDefined();
    if (!txHash) {
      throw new Error("txHash is undefined");
    }

    // 5. Validate with nilauth
    await expect(
      nilauthClient.validatePayment(txHash, payload, payerSigner),
    ).resolves.toBeUndefined();

    // 6. Verify subscription is now active
    const finalStatus = await nilauthClient.subscriptionStatus(
      subscriberDid,
      blindModule,
    );
    expect(finalStatus.subscribed).toBeTruthy();
    expect(finalStatus.details?.expiresAt).toBeGreaterThan(Date.now());
  });
});
