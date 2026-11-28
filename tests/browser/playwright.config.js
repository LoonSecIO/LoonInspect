const { defineConfig } = require("@playwright/test");

module.exports = defineConfig({
  // passkey.spec.js sets its own addresses (#955): localhost, where a passkey can work, and the two where it cannot.
  testMatch: ["smoke.spec.js", "passkey.spec.js"],
  workers: 1,
  reporter: "list",
  use: {
    baseURL: "http://looninspect.test:8001",
    browserName: "chromium",
    locale: "en-US",
    viewport: { width: 1440, height: 900 },
  },
});
