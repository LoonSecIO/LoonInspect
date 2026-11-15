/** Settings › Data Sharing › Promoted applications (#793). The panel is absent where the area is off and nothing is
 *  promoted; with the area off and a title promoted it lists the choice, says it is not being sent and still offers
 *  withdrawal; a held title reads why in words; an excluded candidate says so before the click. Node lane: the
 *  stateless view, rendered to markup. */

import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import type { Promotion, PromotionCandidate, Promotions } from "@/features/system/api";
import { PromotedAppsView, type PromotionsRead } from "@/features/system/PromotedApps";
import { promotionState } from "@/features/system/promotionState";
import { de } from "@/i18n/de";
import { en } from "@/i18n/en";

const TOOL: Promotion = { id: "p1", keyTitle: "v1:" + "a".repeat(64), appName: "Lakeside Tool", bundleId: "io.lakeside.tool",
  promotedAt: "2026-11-15T12:00:00Z", promotedBy: "admin@lakeside.io", deviceCount: 3, versionCount: 2, held: null, excludedBy: null };
const NOTES: PromotionCandidate = { keyTitle: "v1:" + "b".repeat(64), appName: "Lakeside Notes", bundleId: "io.lakeside.notes",
  deviceCount: 1, known: false, excludedBy: null };
const CHROME: PromotionCandidate = { ...NOTES, keyTitle: "v1:" + "c".repeat(64), appName: "Google Chrome", bundleId: "com.google.Chrome", known: true };
const listing = (fields: Partial<Promotions> = {}): Promotions =>
  ({ enabled: true, paused: null, limit: 200, items: [], candidates: [], moreCandidates: 0, ...fields });
const ready = (fields: Partial<Promotions> = {}): PromotionsRead => ({ state: "ready", promotions: listing(fields) });
const nothing = () => undefined;
const view = (read: PromotionsRead, options: { canWrite?: boolean; refusal?: string | null; t?: typeof en } = {}) => {
  const t = options.t ?? en;
  return renderToStaticMarkup(
    <PromotedAppsView read={read} copy={t.system.sharing.promotions} locale={t === en ? "en" : "de"} canWrite={options.canWrite ?? true}
      busy={null} refusal={options.refusal ?? null} query="" onQuery={nothing} onSearch={nothing} onPromote={nothing} onWithdraw={nothing} />
  );
};
// What a sentence reads as in the markup, which escapes text.
const html = (text: string) => text.replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/'/g, "&#x27;");
const words = en.system.sharing.promotions;

describe("promoted applications", () => {
  it("is absent while the area is off and nothing is promoted, and while the read is in flight", () => {
    expect(view(ready({ enabled: false, paused: "flag_off" }))).toBe("");
    expect(view({ state: "loading" })).toBe("");
  });

  it("says a failed read failed, in the server's sentence when one came", () => {
    expect(view({ state: "failed", said: null })).toContain(words.loadFailed);
    expect(view({ state: "failed", said: "The database is unavailable." })).toContain("The database is unavailable.");
  });

  it("with the area off, still lists a promoted title, says it is not sent, and offers withdrawal but no picker", () => {
    const markup = view(ready({ enabled: false, paused: "flag_off", items: [TOOL] }));
    expect(markup).toContain(html(words.paused.flag_off));
    expect(markup).toContain("Lakeside Tool");
    expect(markup).toContain(words.statePaused);
    expect(markup).toContain(words.withdraw);
    expect(markup).not.toContain(words.pickerHeading);
  });

  it.each(["env_disabled", "sharing_off"] as const)("names why nothing leaves when %s", (paused) => {
    expect(view(ready({ paused, items: [TOOL] }))).toContain(html(words.paused[paused]));
  });

  it("reads each state of a promoted title in words", () => {
    expect(promotionState(TOOL, null, words)).toBe(words.stateSending);
    expect(promotionState(TOOL, "sharing_off", words)).toBe(words.statePaused);
    expect(promotionState({ ...TOOL, held: "excluded", excludedBy: "io.lakeside.*" }, null, words)).toBe(words.heldExcluded("io.lakeside.*"));
    expect(promotionState({ ...TOOL, held: "not_installed", deviceCount: 0 }, null, words)).toBe(words.heldNotInstalled);
    // Held back wins over paused: the reason that would still hold once sharing is on is the one to fix.
    expect(promotionState({ ...TOOL, held: "excluded", excludedBy: "io.*" }, "flag_off", words)).toBe(words.heldExcluded("io.*"));
  });

  it("offers candidates, says which a public source knows, and disables an excluded one with its pattern", () => {
    const markup = view(ready({ candidates: [NOTES, CHROME, { ...NOTES, keyTitle: "v1:" + "d".repeat(64), excludedBy: "io.lakeside.*" }], moreCandidates: 4 }));
    expect(markup).toContain(words.unknownTag);
    expect(markup).toContain(words.knownTag);
    expect(markup).toContain(words.excludedTag("io.lakeside.*"));
    expect(markup.match(/<button[^>]*disabled=""[^>]*>Promote<\/button>/g)).toHaveLength(1);
    expect(markup).toContain(words.moreCandidates(4));
    expect(markup).toContain(words.none);
  });

  it("stops offering Promote at the limit", () => {
    const markup = view(ready({ limit: 1, items: [TOOL], candidates: [NOTES] }));
    expect(markup).toMatch(/<button[^>]*disabled=""[^>]*>Promote<\/button>/);
    expect(markup).toContain(words.limit(1, 1));
  });

  it("shows the server's refusal as its own sentence", () => {
    expect(view(ready({ candidates: [NOTES] }), { refusal: "Nothing was promoted: an exclusion covers it." })).toContain("Nothing was promoted: an exclusion covers it.");
  });

  it("gives a read-only role the list and the reason, and no button", () => {
    const markup = view(ready({ items: [TOOL], candidates: [NOTES] }), { canWrite: false });
    expect(markup).toContain(words.readOnly);
    expect(markup).not.toContain(`>${words.withdraw}<`);
    expect(markup).not.toContain(`>${words.promote}<`);
  });

  it("reads in German too", () => {
    const markup = view(ready({ items: [TOOL], candidates: [NOTES] }), { t: de });
    expect(markup).toContain(de.system.sharing.promotions.heading);
    expect(markup).toContain(de.system.sharing.promotions.stateSending);
  });
});
