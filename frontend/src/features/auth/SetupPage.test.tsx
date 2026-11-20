/** First-run setup's claim token. A browser, the container's included, is asked for the token the logs print, exactly
 *  as before; the macOS app's window, whose shell defines this session's token before the page runs, is asked
 *  for nothing it already holds (docs/macos-app.md). Node lane: server rendering, the token a stubbed global.
 *  Then the update check's sentence beside the sharing choice (#819), in English and German. */

import { afterEach, describe, expect, it, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router";
import { SetupPage } from "@/features/auth/SetupPage";
import { de } from "@/i18n/de";
import { en } from "@/i18n/en";

const locale = vi.hoisted(() => ({ code: "en" as "en" | "de" }));
vi.mock("@/i18n/LocaleContext", async () => {
  const dictionaries = { en: (await import("@/i18n/en")).en, de: (await import("@/i18n/de")).de };
  return { useLocale: () => ({ t: dictionaries[locale.code], locale: locale.code }) };
});
afterEach(() => {
  vi.unstubAllGlobals();
  locale.code = "en";
});

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
    // The first field drawn takes the focus the claim field had; that attribute is the only other difference.
    const focused = 'id="displayName" required="" autofocus=""';
    expect(app).toContain(focused);
    expect(browser).not.toContain(focused);
    const [start, end] = [browser.indexOf(CLAIM_BLOCK), browser.indexOf(NEXT_BLOCK)];
    expect(start).toBeGreaterThan(0);
    expect(app.replace(focused, 'id="displayName" required=""')).toBe(browser.slice(0, start) + browser.slice(end));
  });

  it("takes only a non-empty string from the host", () => {
    for (const odd of ["", 42, null, { token: "x" }]) {
      vi.stubGlobal("looninspectSetupClaimToken", odd);
      expect(page()).toContain(CLAIM_BLOCK);
    }
  });
});

// As the markup prints text: React escapes these five.
const escaped = (text: string) =>
  text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#x27;");

describe("first-run setup says what the update check sends (#819)", () => {
  it("in one sentence right after the sharing choice's label, in English and German, with no checkbox of its own", () => {
    for (const [code, t] of [["en", en], ["de", de]] as const) {
      locale.code = code;
      const html = page();
      const said = `<p class="px-1 text-xs text-muted-foreground">${escaped(t.updateCheckNotice.setup)}</p>`;
      expect(html).toContain(`${escaped(t.auth.sharingChoice)}</span></label>${said}`);
      expect(html.match(/type="checkbox"/g)).toHaveLength(1);
    }
    expect(de.updateCheckNotice.setup).not.toBe(en.updateCheckNotice.setup);
  });
});
