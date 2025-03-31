import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/lib.ts"],
  splitting: false,
  sourcemap: true,
  clean: true,
  dts: true,
  format: "esm",
  target: "es2022",
  noExternal: ["fast-deep-equal"],
});
