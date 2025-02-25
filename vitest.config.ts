import tsconfigPaths from "vite-tsconfig-paths";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [tsconfigPaths()],
  test: {
    testTimeout: 0,
    // @ts-expect-error ts not recognising reporter key as per https://vitest.dev/guide/coverage.html#custom-coverage-reporter
    coverage: {
      reporter: ["text", "json-summary", "json"],
      reportOnFailure: true,
    },
  },
});
