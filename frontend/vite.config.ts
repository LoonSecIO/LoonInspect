import path from "node:path";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      // `import.meta.dirname`, not `__dirname`: this file is an ES module, and
      // `__dirname` only works while Vite loads it through a bundling step — the
      // native config loader Vite is moving to has no such step (#21). Node 20.11+.
      "@": path.resolve(import.meta.dirname, "./src")
    }
  },
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: "http://127.0.0.1:8001",
        changeOrigin: true,
        secure: false
      }
    }
  }
});