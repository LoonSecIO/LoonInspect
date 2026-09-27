/** Settings › Intelligence Access (#622): the contribution route's receipt beside paid access. Every state reads in
 *  its own words, the receipt itself never, and the panel is absent where receipts are off and nothing is held or
 *  waiting. Node lane: the stateless view, rendered to markup. */

import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import type { Participation, SharingTier } from "@/features/system/api";
import { ContributionReceiptView, type ReceiptRead } from "@/features/system/ContributionReceipt";
import { receiptState, type ReceiptState } from "@/features/system/receiptState";
import { de } from "@/i18n/de";
import { en } from "@/i18n/en";

const NOW = Date.parse("2026-09-27T12:00:00Z");
const at = (hours: number) => new Date(NOW + hours * 3_600_000).toISOString();
const HELD: Participation = { enabled: true, receiptPresent: true, state: "contributing", acceptedAt: at(-5), updatesUntil: at(30 * 24 - 5),
  withdrawalRequestedAt: null, lastWithdrawalAttemptAt: null, withdrawnAt: null, lastRedeemedAt: null, retryAfter: null, error: null };
const receipt = (fields: Partial<Participation>): Participation => ({ ...HELD, ...fields });
const ready = (participation: Participation | null | undefined, sharing: { tier?: SharingTier; envDisabled?: boolean } = {}): ReceiptRead =>
  ({ state: "ready", now: NOW, sharing: { tier: sharing.tier ?? "keys", envDisabled: sharing.envDisabled ?? false, participation } });
const view = (read: ReceiptRead, t = en) =>
  renderToStaticMarkup(<ContributionReceiptView read={read} copy={t.intelligence} locale={t === en ? "en" : "de"} />);
// What a sentence reads as in the markup, which escapes text.
const html = (text: string) => text.replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/'/g, "&#x27;");
const when = (iso: string) => new Date(iso).toLocaleString("en", { dateStyle: "medium", timeStyle: "short" });
// The value beside one label in the panel's list.
const row = (markup: string, label: string) => markup.match(new RegExp(`<dt>${label}</dt><dd>(.*?)</dd>`))?.[1];
const words = en.intelligence.contribution;

const STATES: [ReceiptState, Participation][] = [
  ["none", receipt({ receiptPresent: false, state: "none", acceptedAt: null, updatesUntil: null })],
  ["contributing", HELD],
  ["lapsed", receipt({ updatesUntil: at(-1) })],
  ["withdrawal_pending", receipt({ state: "withdrawal_pending", withdrawalRequestedAt: at(-2), lastWithdrawalAttemptAt: at(-1) })],
  ["withdrawn", receipt({ receiptPresent: false, state: "withdrawn", withdrawnAt: at(-1) })],
  ["ended", receipt({ receiptPresent: false, state: "ended" })],
  ["unknown", receipt({ state: "suspended" })]
];

describe("the community contribution panel on Settings › Intelligence Access (#622)", () => {
  it("names every state in its own words, in both languages, a receipt past its deadline included", () => {
    for (const t of [en, de]) {
      const copy = t.intelligence.contribution;
      for (const [state, each] of STATES) {
        expect(receiptState(each, NOW)).toBe(state);
        const markup = view(ready(each), t);
        expect(markup).toContain(`<span class="font-medium">${html(copy.states[state])}</span>`);
        expect(markup).toContain(html(copy.explained[state]));
      }
      expect(new Set(STATES.map(([state]) => copy.states[state])).size).toBe(STATES.length);
      expect(new Set(STATES.map(([state]) => copy.explained[state])).size).toBe(STATES.length);
    }
  });

  it("says whether a receipt is held, and never the receipt, even were the status to carry one", () => {
    const leaked = { ...HELD, receipt: "loon_rcpt_" + "R".repeat(43) } as Participation;
    for (const t of [en, de]) {
      const markup = view(ready(leaked), t);
      expect(row(markup, t.intelligence.contribution.receipt)).toBe(html(t.intelligence.contribution.held));
      expect(markup).not.toContain("loon_rcpt_");
    }
    expect(row(view(ready(STATES[0][1])), words.receipt)).toBe(words.notHeld);
  });

  it("is absent where receipts are off and nothing is held or waiting, and says so where something still is", () => {
    // `enabled` is how CONTRIBUTION_RECEIPTS reaches the page, with the two corpus switches it needs beside it.
    const off = { enabled: false, receiptPresent: false };
    for (const each of [null, undefined, receipt({ ...off, state: "none" }), receipt({ ...off, state: "withdrawn" }), receipt({ ...off, state: "ended" })])
      expect(view(ready(each))).toBe("");
    expect(view({ state: "loading" })).toBe("");
    // Switched off after one was earned: the receipt fetches nothing, and a waiting withdrawal still holds uploads.
    for (const each of [receipt({ enabled: false, retryAfter: at(1) }), receipt({ enabled: false, state: "withdrawal_pending" })]) {
      const markup = view(ready(each));
      expect(markup).toContain(html(words.receiptsOff));
      expect(row(markup, words.nextFetch)).toBe(words.noneScheduled);
    }
    expect(view(ready(HELD))).not.toContain(html(words.receiptsOff));
    expect([en, de].map(({ intelligence: { contribution } }) => ["CONTRIBUTION_RECEIPTS", "VULN_TENANT_SELECTION", "VULN_RELEASE_RETENTION"]
      .every((name) => contribution.receiptsOff.includes(name)))).toEqual([true, true]);
  });

  it("promises a next fetch only while the receipt can be used, and names the override when it is the reason", () => {
    const due = receipt({ retryAfter: at(1), lastRedeemedAt: at(-3) });
    expect([row(view(ready(due)), words.nextFetch), row(view(ready(due)), words.lastFetched)]).toEqual([html(when(at(1))), html(when(at(-3)))]);
    expect([row(view(ready(HELD)), words.nextFetch), row(view(ready(HELD)), words.lastFetched)]).toEqual([words.noneScheduled, words.notYet]);
    const unusable: [Participation, { tier?: SharingTier; envDisabled?: boolean }][] = [[due, { envDisabled: true }], [due, { tier: "off" }],
      [receipt({ ...due, updatesUntil: at(-1) }), {}], [receipt({ ...due, state: "withdrawal_pending" }), {}], [receipt({ ...due, state: "withdrawn" }), {}]];
    for (const [each, sharing] of unusable) expect(row(view(ready(each, sharing)), words.nextFetch)).toBe(words.noneScheduled);
    expect(view(ready(due, { envDisabled: true }))).toContain(html(words.envOverride));
    expect(view(ready(due))).not.toContain(html(words.envOverride));
  });

  it("shows the authorization date only for a receipt still stored as in force, a passed one included", () => {
    const until = at(24 * 20);
    expect(row(view(ready(receipt({ updatesUntil: until }))), en.intelligence.until)).toBe(html(when(until)));
    expect(row(view(ready(receipt({ updatesUntil: at(-1) }))), en.intelligence.until)).toBe(html(when(at(-1))));
    for (const state of ["withdrawal_pending", "withdrawn", "ended"])
      expect(row(view(ready(receipt({ state, updatesUntil: until }))), en.intelligence.until)).toBe(en.intelligence.none);
  });

  it("says the last error sentence, and the withdrawal's progress while it waits", () => {
    const failure = "Could not reach https://api.example.org to withdraw. Check DNS and network access; the withdrawal is retried automatically, and uploads stay held until it is acknowledged.";
    const markup = view(ready(receipt({ state: "withdrawal_pending", withdrawalRequestedAt: at(-2), error: failure })));
    expect(markup).toContain(`<p role="alert" class="text-sm text-destructive">${html(failure)}</p>`);
    expect([row(markup, words.withdrawalRequested), row(markup, words.withdrawalAttempt)]).toEqual([html(when(at(-2))), words.notYet]);
    expect(view(ready(HELD))).not.toContain(words.withdrawalRequested);
    expect(view(ready(HELD))).not.toContain('role="alert"');
    expect(row(view(ready(STATES[4][1])), words.withdrawnAt)).toBe(html(when(at(-1))));
  });

  it("says both routes can be present, which one refreshes, and what the receipt sends, in both languages", () => {
    for (const t of [en, de]) {
      const copy = t.intelligence.contribution;
      const markup = view(ready(HELD), t);
      for (const line of [copy.both, copy.whichRefreshes, copy.disclosure]) expect(markup).toContain(html(line));
    }
  });

  it("says a failed read, in the server's words when it gave some", () => {
    expect(view({ state: "failed", said: null })).toContain(html(words.loadFailed));
    expect(view({ state: "failed", said: "Insufficient permissions" })).toContain(">Insufficient permissions</p>");
  });
});
