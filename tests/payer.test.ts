import { randomBytes } from "node:crypto";
import { beforeAll, describe, it } from "vitest";
import { PayerBuilder } from "#/payer/builder";
import type { Payer } from "#/payer/client";
import { createSignerFromKey } from "#/payer/wallet";
import { Env, PrivateKeyPerSuite } from "./helpers";

describe("Payer", () => {
  let payer: Payer;

  beforeAll(async () => {
    const signer = await createSignerFromKey(PrivateKeyPerSuite.Payer);
    payer = await new PayerBuilder()
      .chainUrl(Env.nilChainUrl)
      .signer(signer)
      .build();
  });

  it("can pay", async ({ expect }) => {
    const tx = await payer.pay(randomBytes(16), 50000);
    expect(tx).toBeTruthy();
  });
});
