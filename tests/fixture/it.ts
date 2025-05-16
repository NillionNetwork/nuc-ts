import * as vitest from "vitest";
import type { NilauthClient } from "#/nilauth/client";
import { buildFixture, type TestFixture } from "./fixture";

type FixtureContext = {
  nilauthClient: NilauthClient;
};

type TestFixtureExtension = {
  it: vitest.TestAPI<FixtureContext>;
  beforeAll: (fn: (ctx: FixtureContext) => Promise<void>) => void;
};

export function createTestFixtureExtension(key: string): TestFixtureExtension {
  let fixture: TestFixture;

  // biome-ignore-start lint/correctness/noEmptyPattern: Vitest fixture API requires this parameter structure
  const it = vitest.test.extend<FixtureContext>({
    nilauthClient: async ({}, use) => {
      if (!fixture) throw new Error("Fixture is not initialized");
      await use(fixture.nilauthClient);
    },
  });
  // biome-ignore-end lint/correctness/noEmptyPattern: Vitest fixture API requires this parameter structure

  const beforeAll = (fn: (ctx: FixtureContext) => Promise<void>) =>
    vitest.beforeAll(async () => {
      fixture = await buildFixture(key);
      await fn(fixture);
    });

  return { it, beforeAll };
}
