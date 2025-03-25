import { randomBytes } from "node:crypto";
import { describe } from "vitest";
import { Env } from "./fixture/env";
import { createTestFixtureExtension } from "./fixture/it";

describe("Payer", () => {
  const { it, beforeAll } = createTestFixtureExtension(Env.Payer);

  beforeAll(async () => {});

  it("can pay", async ({ expect, payer }) => {
    const tx = await payer.pay(randomBytes(16), 50000);
    expect(tx).toBeTruthy();
  });
});
