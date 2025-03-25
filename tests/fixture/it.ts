import * as vitest from "vitest";
import type { AuthorityService } from "#/authority";
import type { Payer } from "#/payer/client";
import type { Wallet } from "#/payer/wallet";
import type { AuthorityServer } from "./authority-server";
import { type TestFixture, buildFixture } from "./fixture";

type FixtureContext = {
  signer: Wallet;
  payer: Payer;
  authorityServer: AuthorityServer;
  authorityService: AuthorityService;
};

type TestFixtureExtension = {
  it: vitest.TestAPI<FixtureContext>;
  beforeAll: (fn: (ctx: FixtureContext) => Promise<void>) => void;
  afterAll: (fn: (ctx: FixtureContext) => Promise<void>) => void;
  afterEach: (fn: (ctx: FixtureContext) => Promise<void>) => void;
};

export function createTestFixtureExtension(key: string): TestFixtureExtension {
  let fixture: TestFixture;

  const it = vitest.test.extend<FixtureContext>({
    // biome-ignore lint/correctness/noEmptyPattern: <explanation>
    signer: async ({}, use) => {
      if (!fixture) throw new Error("Fixture not initialized");
      await use(fixture.signer);
    },
    // biome-ignore lint/correctness/noEmptyPattern: <explanation>
    payer: async ({}, use) => {
      if (!fixture) throw new Error("Fixture not initialized");
      await use(fixture.payer);
    },
    // biome-ignore lint/correctness/noEmptyPattern: <explanation>
    authorityServer: async ({}, use) => {
      if (!fixture) throw new Error("Fixture not initialized");
      await use(fixture.authorityServer);
    },
    // biome-ignore lint/correctness/noEmptyPattern: <explanation>
    authorityService: async ({}, use) => {
      if (!fixture) throw new Error("Fixture not initialized");
      await use(fixture.authorityService);
    },
  });

  const beforeAll = (fn: (ctx: FixtureContext) => Promise<void>) =>
    vitest.beforeAll(async () => {
      fixture = await buildFixture(key);
      await fn(fixture);
    });

  const afterAll = (fn: (ctx: FixtureContext) => Promise<void>) =>
    vitest.afterAll(async () => {
      fixture.authorityServer.close();
      await fn(fixture);
    });

  const afterEach = (fn: (ctx: FixtureContext) => Promise<void>) =>
    vitest.afterEach(async () => {
      fixture.authorityServer.resetHandlers();
      await fn(fixture);
    });

  return { it, beforeAll, afterAll, afterEach };
}
