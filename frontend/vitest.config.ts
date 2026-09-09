import { defineConfig, mergeConfig } from "vitest/config";
// With its extension, for the same native loader (#21): Node resolves a relative
// import literally, and `allowImportingTsExtensions` in tsconfig.json lets TypeScript
// accept the `.ts` here.
import viteConfig from "./vite.config.ts";

// The frontend test lane (#285, #138): node environment only, deliberately. The suite
// covers pure modules — the ones that encode rulings — and a DOM would invite render
// tests, which is the scope the issue refuses. `mergeConfig` keeps the `@` alias from
// vite.config.ts so a test imports a module by the same path the app does.
export default mergeConfig(
  viteConfig,
  defineConfig({
    test: {
      environment: "node",
      include: ["src/**/*.test.ts"]
    }
  })
);
