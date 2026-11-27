const { defineConfig } = require("@playwright/test");

module.exports = defineConfig({
  testMatch: "smoke.spec.js",
  workers: 1,
  reporter: "list",
  use: {
    baseURL: "http://looninspect.test:8001",
    browserName: "chromium",
    locale: "en-US",
    viewport: { width: 1440, height: 900 },
  },
});
