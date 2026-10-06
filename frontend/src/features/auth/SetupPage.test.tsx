/** First-run setup's claim token. A browser, the container's included, is asked for the token the logs print, exactly
 *  as before; the macOS app spike's window, whose shell defines this session's token before the page runs, is asked
 *  for nothing it already holds (docs/spike-macos-app.md). Node lane: server rendering, the token a stubbed global. */

import { afterEach, describe, expect, it, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router";
import { SetupPage } from "@/features/auth/SetupPage";
import { en } from "@/i18n/en";

vi.mock("@/i18n/LocaleContext", async () => {
  const { en: t } = await import("@/i18n/en");
  return { useLocale: () => ({ t, locale: "en" }) };
});
afterEach(() => vi.unstubAllGlobals());

const page = () =>
  renderToStaticMarkup(
    <MemoryRouter>
      <SetupPage />
    </MemoryRouter>
  );
const CLAIM_BLOCK = '<div class="space-y-2"><label for="claimToken"';
const NEXT_BLOCK = '<div class="space-y-2"><label for="displayName"';

describe("first-run setup's claim token", () => {
  it("is asked for, with the docker compose logs help, wherever no host hands one over", () => {
    const html = page();
    expect(html).toContain(CLAIM_BLOCK);
    expect(html).toMatch(/<input [^>]*id="claimToken" required="" autofocus=""/);
    expect(html).toContain(`<p class="text-xs text-muted-foreground">${en.auth.claimTokenHelp}</p>`);
    expect(html).toContain("docker compose logs app | grep &quot;claim token&quot;</pre>");
  });

  it("is not asked for in the app's window, which holds it; the rest of the page is the browser's, byte for byte", () => {
    const browser = page();
    vi.stubGlobal("looninspectSetupClaimToken", "a-claim-token");
    const app = page();
    for (const gone of ["claimToken", en.auth.claimTokenHelp, "docker compose", "a-claim-token"]) expect(app).not.toContain(gone);
    const [start, end] = [browser.indexOf(CLAIM_BLOCK), browser.indexOf(NEXT_BLOCK)];
    expect(start).toBeGreaterThan(0);
    expect(app).toBe(browser.slice(0, start) + browser.slice(end));
  });

  it("takes only a non-empty string from the host", () => {
    for (const odd of ["", 42, null, { token: "x" }]) {
      vi.stubGlobal("looninspectSetupClaimToken", odd);
      expect(page()).toContain(CLAIM_BLOCK);
    }
  });
});
