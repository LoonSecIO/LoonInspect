/** Report an incorrect match (#623): offered on a `covered` build that names a finding, to an administrator while the
 *  preview is on and the list names its release; the finding is picked from the row's ids alone, and the preview
 *  request carries the pick and the release. Frontend lane (#285), node only, as submissions.test.tsx. */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router";
import type { CatalogEntry } from "@/features/catalog/types";
import { askPreview, bodyOf, caseOf, correctionFor, dialog, OPENED, type Dialog, type Move, type Named } from "@/features/submissions/dialog";
import { ReportMatch, SubmissionView } from "@/features/submissions/SubmissionDialog";
import { de } from "@/i18n/de";
import { en } from "@/i18n/en";

const copy = en.submissions;
const RELEASE = "4f1c".repeat(16); // a manifest signature: 64 lowercase hex
const IDS = ["CVE-2024-0208", "CVE-2024-0209", "LoonVD-2026-000042"];
const ROW = { id: 9, name: "Wireshark", bundleId: "org.wireshark.Wireshark", version: "4.2.0", shortVersion: null, platform: "macos",
  vuln: { assessment: "covered", corpusAsOf: "2026-09-20", counts: { total: 17 }, vulnIDs: IDS, vulnIDsTruncated: true } } as unknown as CatalogEntry;
const NAMED = correctionFor(ROW, true, true, RELEASE)!.named;

const answers: Response[] = [];
const fetchStub = vi.fn<typeof fetch>(async () => answers.shift() ?? Promise.reject(new TypeError("Failed to fetch")));
const view = (state: Dialog, findings: string[], named: Named = NAMED, t = en) => renderToStaticMarkup(<MemoryRouter>
  <SubmissionView named={named} findings={findings} state={state} copy={t.submissions} dispatch={() => {}} onPreview={() => {}} onSend={() => {}} onClose={() => {}} />
</MemoryRouter>);
const options = (markup: string) => [...markup.matchAll(/<option[^>]*>([^<]*)<\/option>/g)].map((match) => match[1]);
const action = (entry: CatalogEntry, canWrite: boolean, enabled: boolean, release: string | null, t = en) =>
  renderToStaticMarkup(<ReportMatch entry={entry} canWrite={canWrite} enabled={enabled} release={release} t={t} />);

// apiRequest reads the CSRF cookie before a POST, and this lane has no DOM to hold one.
beforeEach(() => { vi.stubGlobal("document", { cookie: "" }); vi.stubGlobal("fetch", fetchStub); });
afterEach(() => { vi.unstubAllGlobals(); fetchStub.mockClear(); answers.length = 0; });

describe("Report an incorrect match on the Vulnerabilities page", () => {
  it("is offered on a covered build that names a finding: the row's own build, its ids to pick from, and the list's release", () => {
    expect(correctionFor(ROW, true, true, RELEASE)).toEqual(
      { named: { ...caseOf(ROW, "coverage"), kind: "correction", finding: IDS[0], findingRelease: RELEASE }, findings: IDS });
    expect(action(ROW, true, true, RELEASE)).toMatch(new RegExp(`<button[^>]*>${copy.reportMatch}</button>`));
    expect(action(ROW, true, true, RELEASE, de)).toContain(`>${de.submissions.reportMatch}</button>`);
  });

  it("is absent for a viewer, with the preview off, with no release, and on a row with no finding to name", () => {
    const vuln = (shape: object) => ({ ...ROW, vuln: shape }) as unknown as CatalogEntry;
    const refused: [CatalogEntry, boolean, boolean, string | null][] = [[ROW, false, true, RELEASE], [ROW, true, false, RELEASE],
      [ROW, true, true, null], [vuln({ ...ROW.vuln, counts: { total: 0 }, vulnIDs: [] }), true, true, RELEASE],
      [vuln({ assessment: "unknown_app", corpusAsOf: "2026-09-20" }), true, true, RELEASE], [vuln({ assessment: "off" }), true, true, RELEASE],
      [{ ...ROW, platform: "watchos" }, true, true, RELEASE]];
    for (const [entry, canWrite, enabled, release] of refused) {
      expect(correctionFor(entry, canWrite, enabled, release)).toBeNull();
      expect(action(entry, canWrite, enabled, release)).toBe("");
    }
  });
});

describe("the finding", () => {
  it("is picked from the row's ids alone, and a pick is an edit: the preview and permission go", () => {
    expect(options(view(OPENED, IDS))).toEqual(IDS);
    expect(view(OPENED, IDS)).toContain(`<option selected="">${IDS[0]}</option>`);
    const shown = { body: bodyOf(NAMED, OPENED.typed), answer: { payload: {}, excludedBy: null } };
    const ready = ([{ type: "previewed", shown }, { type: "ticked", box: "permission", on: true }] as Move[]).reduce(dialog, OPENED);
    const picked = dialog(ready, { type: "typed", field: "finding", value: IDS[2] });
    expect(picked).toMatchObject({ shown: null, permission: false });
    expect(bodyOf(NAMED, picked.typed)).toMatchObject({ finding: IDS[2], findingRelease: RELEASE });
    expect(view(picked, IDS)).toContain(`<option selected="">${IDS[2]}</option>`);
    // One id is named, not offered: no select, and German reads the same way.
    const one = view(OPENED, [IDS[0]], NAMED, de);
    expect(one).not.toContain("<select");
    expect(one).toContain(`${de.submissions.findingLabel}<span class="block font-mono">${IDS[0]}</span>`);
  });

  it("rides the preview request with the release, and the preview prints the pair it answers", async () => {
    const payload = { contract: "v2", kind: "correction", app_name: "Wireshark", finding: IDS[1], finding_release: RELEASE };
    answers.push(new Response(JSON.stringify({ payload, excludedBy: null }), { status: 200 }));
    const typed = dialog(OPENED, { type: "typed", field: "finding", value: IDS[1] }).typed;
    const move = await askPreview(bodyOf(NAMED, typed), copy.failed);
    const [url, init] = fetchStub.mock.calls[0];
    expect([url, init?.method]).toEqual(["/api/submissions/preview", "POST"]);
    expect(JSON.parse(String(init?.body))).toEqual({ ...NAMED, finding: IDS[1], publicUrl: null, text: null, contact: null });
    const markup = view(dialog({ ...OPENED, typed }, move), IDS);
    for (const pair of [`&quot;finding&quot;: &quot;${IDS[1]}&quot;`, `&quot;finding_release&quot;: &quot;${RELEASE}&quot;`]) expect(markup).toContain(pair);
  });
});
