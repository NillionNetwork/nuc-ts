import { loadEnv } from "vite";
import tsconfigPaths from "vite-tsconfig-paths";
import { defineConfig } from "vitest/config";

export default defineConfig(({ mode }) => ({
  plugins: [tsconfigPaths()],
  test: {
    testTimeout: 0,
    globalSetup: "./tests/fixture/global-setup.ts",
    env: loadEnv(mode, process.cwd(), ""),
    coverage: {
      reporter: ["text", "json-summary", "json"],
      reportOnFailure: true,
    },
  },
}));
