/** Settings › Intelligence Access (#623): the organization's private case list. Every state reads in its own word,
 *  Refresh keeps the service's one-minute floor, Withdraw asks first and posts once. Node lane, stubbed apiRequest. */

import { afterEach, describe, expect, it, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { ApiError, apiRequest } from "@/config/api";
import { useHasPermission } from "@/features/auth/store";
import { PERMISSIONS } from "@/features/auth/types";
import type { SubmissionCaseOut } from "@/features/submissions/api";
import { act, asksStatus, handlers, refreshWait, replaceCase, type RowAct } from "@/features/submissions/cases";
import { SubmissionCasesView, type CasesRead } from "@/features/submissions/SubmissionCases";
import { IntelligenceAccessPage } from "@/features/system/IntelligenceAccessPage";
import { de } from "@/i18n/de";
import { en } from "@/i18n/en";

vi.mock("@/config/api", async (importOriginal) => ({ ...(await importOriginal<typeof import("@/config/api")>()), apiRequest: vi.fn() }));
vi.mock("@/features/auth/store", async (importOriginal) => ({ ...(await importOriginal<typeof import("@/features/auth/store")>()), useHasPermission: vi.fn() }));
vi.mock("@/i18n/LocaleContext", async () => {
  const { en: t } = await import("@/i18n/en");
  return { useLocale: () => ({ t, locale: "en" }) };
});
afterEach(() => vi.clearAllMocks());

const copy = en.submissionCases;
const NOW = Date.parse("2026-09-26T12:00:00Z");
const ago = (seconds: number) => new Date(NOW - seconds * 1000).toISOString();
const STATES = ["pending", "received", "reviewing", "needs_information", "accepted", "published", "declined", "withdrawn", "expired"] as const;
const RELEASE = "0f".repeat(32);
const CASE: SubmissionCaseOut = { id: "c0", createdAt: ago(3600), kind: "coverage", appName: "Wireshark", bundleId: "org.wireshark.Wireshark",
  platform: "macos", versions: ["3.6.2"], publicUrl: null, text: null, contact: null, finding: null, findingRelease: null, state: "received",
  receivedAt: ago(3599), closedAt: null, release: null, coverage: null, note: null, lastStatusAt: null, retryAt: null, lastError: null,
  withdrawnAt: null, excludedOverride: false, permissionAt: ago(3600) };
const one = (id: string, fields: Partial<SubmissionCaseOut> = {}): SubmissionCaseOut => ({ ...CASE, id, ...fields });
const ready = (cases: SubmissionCaseOut[], enabled = true): CasesRead => ({ state: "ready", enabled, cases });
const view = (read: CasesRead, acts: Record<string, RowAct> = {}, t = en) => renderToStaticMarkup(
  <SubmissionCasesView read={read} copy={t.submissionCases} locale={t === en ? "en" : "de"} now={NOW} acts={acts} />);
const buttons = (markup: string, label: string) => markup.match(new RegExp(`<button[^>]*>${label}</button>`, "g")) ?? [];
// What a sentence reads as in the markup, which escapes text.
const html = (text: string) => text.replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/'/g, "&#x27;");

describe("the case list on Settings › Intelligence Access (#623)", () => {
  it("names every state in its own word, and a release with its coverage on a published case only", () => {
    const every = STATES.map((state) => one(state, { state, release: RELEASE, coverage: "Both observed builds are assessed." }));
    for (const t of [en, de]) {
      const markup = view(ready(every), {}, t);
      const words = STATES.map((state) => t.submissionCases.states[state]);
      expect(new Set(words).size).toBe(STATES.length);
      words.forEach((word) => expect(markup).toContain(`>${word}</p>`));
      expect(markup.split(RELEASE)).toHaveLength(2); // `accepted` is not covered; only `published` names a release
      expect(markup.split("Both observed builds are assessed.")).toHaveLength(2);
    }
  });

  it("says what the reviewer wrote, the last failure, and a withdrawal the service has not confirmed; never a key", () => {
    const failure = "No answer came from the intelligence service at api.example.org. Check DNS, network access and INTELLIGENCE_ENDPOINT, then try again; the case keeps its key.";
    const markup = view(ready([one("a", { state: "needs_information", note: "Which build do you run?" }), one("d", { state: "expired", withdrawnAt: ago(60) }),
      one("b", { state: "declined", note: "The feed already covers 3.6.2." }), one("c", { lastError: failure, withdrawnAt: ago(60) })]));
    expect(markup).toContain(`${copy.question} Which build do you run?`);
    expect(markup).toContain(`${copy.reason} The feed already covers 3.6.2.`);
    expect(markup).toContain(failure);
    // Once: an expired case is deleted there, so a withdrawal is left to confirm on the live one alone.
    expect(markup.split(copy.unconfirmed(new Date(ago(60)).toLocaleString("en", { dateStyle: "medium", timeStyle: "short" })))).toHaveLength(2);
    expect(markup).not.toMatch(/loon_case_|case_?key/i);
  });

  it("still lists with the preview off, saying new cases cannot be sent, and says an empty list in one line", () => {
    const off = view(ready([one("a")], false));
    expect(off).toContain(copy.notEnabled);
    expect([buttons(off, copy.refresh), buttons(off, copy.withdraw)].map((found) => found.length)).toEqual([1, 1]);
    expect(view(ready([]))).toContain(copy.empty);
    expect(view(ready([]))).not.toContain("<li");
    expect([view({ state: "failed", said: null }), view({ state: "failed", said: "Insufficient permissions" })]).toEqual(
      [expect.stringContaining(copy.loadFailed), expect.stringContaining(">Insufficient permissions</p>")]);
  });

  it("holds Refresh 60 seconds after the last read and until retryAt, counting down, and shows a 429 as the server said it", async () => {
    expect([15, 59.5, 60].map((seconds) => refreshWait(one("a", { lastStatusAt: ago(seconds) }), NOW))).toEqual([45, 1, 0]);
    expect(refreshWait(one("a", { lastStatusAt: ago(90), retryAt: ago(-30) }), NOW)).toBe(30);
    expect(buttons(view(ready([one("a", { lastStatusAt: ago(15) })])), copy.refreshIn(45))[0]).toContain('disabled=""');
    expect(buttons(view(ready([one("a", { lastStatusAt: ago(61) })])), copy.refresh)[0]).not.toContain('disabled=""');
    expect(buttons(view(ready([one("a")]), { a: { busy: true } }), copy.refresh)[0]).toContain('disabled=""');
    // Never a case the service has not received or has expired, where the route asks nothing, nor a withdrawn one, which is final.
    expect(STATES.filter((state) => asksStatus(one("a", { state })))).toEqual(["received", "reviewing", "needs_information", "accepted", "published", "declined"]);
    const soon = "Asked too soon: a case's status is read once a minute, and not before a time the service gave. Try again in 37 seconds.";
    vi.mocked(apiRequest).mockRejectedValueOnce(new ApiError(429, soon));
    expect(await act("status", "a", "fallback")).toEqual({ error: soon });
    expect(apiRequest).toHaveBeenCalledWith("/submissions/a/status", { method: "POST" });
    expect(view(ready([one("a")]), { a: { error: soon } })).toContain(`<p role="alert" class="text-destructive">${html(soon)}</p>`);
    vi.mocked(apiRequest).mockRejectedValueOnce(new TypeError("Failed to fetch"));
    expect(await act("status", "a", copy.failed)).toEqual({ error: copy.failed });
  });

  it("asks before it withdraws, even a closed case; posts once; and puts the answer in the row's place", async () => {
    expect(buttons(view(ready(STATES.map((state) => one(state, { state })))), copy.withdraw)).toHaveLength(STATES.length - 1);
    const cases = [one("a", { state: "declined" }), one("b")];
    const asking = view(ready(cases), { a: { confirming: true } });
    expect(asking).toContain(copy.withdrawConfirm);
    expect(buttons(asking, copy.withdraw)).toHaveLength(1); // the asked row's button makes way for the question
    expect(buttons(view(ready(cases), { a: { confirming: true, busy: true } }), copy.confirm)[0]).toContain('disabled=""');
    const answer = one("a", { state: "withdrawn", withdrawnAt: ago(0) });
    vi.mocked(apiRequest).mockResolvedValueOnce(answer);
    expect(await Promise.all([act("withdraw", "a", "fallback"), act("withdraw", "a", "fallback")])).toEqual([{ item: answer }, null]);
    expect(apiRequest).toHaveBeenCalledTimes(1);
    expect(apiRequest).toHaveBeenCalledWith("/submissions/a/withdraw", { method: "POST" });
    const after = replaceCase(cases, answer);
    expect(after).toEqual([answer, cases[1]]);
    const settled = view(ready(after));
    expect(buttons(settled, copy.withdraw)).toHaveLength(1);
    expect(settled).not.toContain("has not confirmed"); // a confirmed withdrawal is only its state word
  });

  it("wires the row's buttons: asking and cancelling only mark it, and Withdraw's question stays up while it posts once", async () => {
    let acts: Record<string, RowAct> = { a: { confirming: true } };
    const settle = vi.fn(), on = handlers((next) => void (acts = next(acts)), copy.failed, settle);
    vi.mocked(apiRequest).mockResolvedValueOnce(one("a", { state: "withdrawn" })).mockRejectedValueOnce(new ApiError(429, "Asked too soon."));
    const posting = [on.withdraw("a"), on.withdraw("a")];
    expect(acts).toEqual({ a: { confirming: true, busy: true } });
    await Promise.all([...posting, on.refresh("b"), on.ask("c"), on.cancel("d")]);
    expect([acts, settle.mock.calls]).toEqual([{ a: {}, b: { error: "Asked too soon." }, c: { confirming: true }, d: {} }, [[one("a", { state: "withdrawn" }), expect.any(Number)]]]);
    expect(vi.mocked(apiRequest).mock.calls.map(([path]) => path)).toEqual(["/submissions/a/withdraw", "/submissions/b/status"]);
  });

  it("is an administrator's section: absent for a reader without SYSTEM_WRITE, beside the paid panel for one with it", () => {
    vi.mocked(useHasPermission).mockImplementation((permission) => permission === PERMISSIONS.SYSTEM_READ);
    expect(renderToStaticMarkup(<IntelligenceAccessPage />)).not.toContain(copy.title);
    vi.mocked(useHasPermission).mockReturnValue(true);
    const page = renderToStaticMarkup(<IntelligenceAccessPage />);
    expect([page.includes(`aria-label="${copy.title}"><h2`), page.includes(copy.loading)]).toEqual([true, true]);
  });
});
