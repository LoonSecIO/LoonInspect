import { defineConfig, mergeConfig } from "vitest/config";
// With its extension, for the same native loader (#21): Node resolves a relative
// import literally, and `allowImportingTsExtensions` in tsconfig.json lets TypeScript
// accept the `.ts` here.
import viteConfig from "./vite.config.ts";

// The frontend test lane (#285, #138): node environment by default, deliberately. The suite
// covers pure modules and the stateless summary views requested in #594 review.
// Those views use server rendering. A test whose subject is effects and browser events (the
// run-now poller's, useRunLog.test.tsx) opts into jsdom on its own first line,
// `// @vitest-environment jsdom`, and the lane stays node. `mergeConfig` keeps the `@` alias from
// vite.config.ts so a test imports a module by the same path the app does.
export default mergeConfig(
  viteConfig,
  defineConfig({
    test: {
      environment: "node",
      include: ["src/**/*.test.{ts,tsx}"]
    }
  })
);
