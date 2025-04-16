import * as vitest from "vitest";
import type { NilauthClient } from "#/nilauth/client";
import { type TestFixture, buildFixture } from "./fixture";

type FixtureContext = {
  nilauthClient: NilauthClient;
};

type TestFixtureExtension = {
  it: vitest.TestAPI<FixtureContext>;
  beforeAll: (fn: (ctx: FixtureContext) => Promise<void>) => void;
};

export function createTestFixtureExtension(key: string): TestFixtureExtension {
  let fixture: TestFixture;

  const it = vitest.test.extend<FixtureContext>({
    // biome-ignore lint/correctness/noEmptyPattern: <explanation>
    nilauthClient: async ({}, use) => {
      if (!fixture) throw new Error("Fixture not initialized");
      await use(fixture.nilauthClient);
    },
  });

  const beforeAll = (fn: (ctx: FixtureContext) => Promise<void>) =>
    vitest.beforeAll(async () => {
      fixture = await buildFixture(key);
      await fn(fixture);
    });

  return { it, beforeAll };
}
