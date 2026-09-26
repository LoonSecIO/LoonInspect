/** Request coverage (#623): the dialog prints the preview's own payload, Send waits for a preview of exactly the
 *  fields and for the one-time boxes, a press in flight sends nothing, and a refusal is the server's sentence.
 *  Frontend lane (#285), node only: moves run through the reducer, requests through a stubbed fetch. */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router";
import type { CatalogEntry } from "@/features/catalog/types";
import { listSubmissions, submissionStatus, withdrawSubmission, type SubmissionCaseOut } from "@/features/submissions/api";
import { askPreview, askSend, bodyOf, canSend, coverageFor, dialog, OPENED, oneAtATime, type Dialog, type Move, type Shown } from "@/features/submissions/dialog";
import { RequestCoverage, SubmissionView } from "@/features/submissions/SubmissionDialog";
import { de } from "@/i18n/de";
import { en } from "@/i18n/en";

const copy = en.submissions;
const ROW = { id: 7, name: "Wireshark", bundleId: "org.wireshark.Wireshark", version: "3.6.2", shortVersion: "3.6.2 (1)", platform: "macos",
  vuln: { assessment: "unknown_app", corpusAsOf: "2026-09-20" } } as unknown as CatalogEntry;
const NAMED = coverageFor(ROW, true, true)!;
// backend/app/core/submissions.py's `payload_for` for ROW: the contract's own names, and no case key.
const PAYLOAD = { contract: "v2", kind: "coverage", app_name: "Wireshark", bundle_id: "org.wireshark.Wireshark", platform: "macos", versions: ["3.6.2", "3.6.2 (1)"] };
const SHOWN: Shown = { body: bodyOf(NAMED, OPENED.typed), answer: { payload: PAYLOAD, excludedBy: null } };
const CASE = { id: "0192f1e0-5b3c-7000-8000-000000000001", state: "received", lastError: null } as SubmissionCaseOut;
const EXCLUDED = `Nothing was sent: org.wireshark.Wireshark matches "org.wireshark.*" on this organization's data-sharing exclusion list. This one case needs the one-time override; the list stays.`;

const answers: Response[] = [];
const fetchStub = vi.fn<typeof fetch>(async () => answers.shift() ?? Promise.reject(new TypeError("Failed to fetch")));
const reply = (status: number, body: unknown) => new Response(JSON.stringify(body), { status });
const request = (call: number) => ({ url: fetchStub.mock.calls[call][0], method: fetchStub.mock.calls[call][1]?.method,
  body: JSON.parse(String(fetchStub.mock.calls[call][1]?.body ?? "null")) });
const run = (...moves: Move[]) => moves.reduce(dialog, OPENED);
const ready = run({ type: "asked" }, { type: "previewed", shown: SHOWN }, { type: "ticked", box: "permission", on: true });
const view = (state: Dialog, t = en) => renderToStaticMarkup(
  <MemoryRouter><SubmissionView named={NAMED} state={state} copy={t.submissions} dispatch={() => {}} onPreview={() => {}} onSend={() => {}} onClose={() => {}} /></MemoryRouter>);
// What a string reads as in the markup, which escapes text.
const html = (text: string) => text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#x27;");
const button = (markup: string, label: string) => markup.match(new RegExp(`<button[^>]*>${label}</button>`))?.[0] ?? "";

// apiRequest reads the CSRF cookie before a POST, and this lane has no DOM to hold one.
beforeEach(() => { vi.stubGlobal("document", { cookie: "" }); vi.stubGlobal("fetch", fetchStub); });
afterEach(() => { vi.unstubAllGlobals(); fetchStub.mockClear(); answers.length = 0; });

describe("the preview", () => {
  it("posts the row's build and prints the answer's own payload, whatever it holds", async () => {
    const payload = { ...PAYLOAD, added_by_the_server: "a key this page never builds" };
    answers.push(reply(200, { payload, excludedBy: null }));
    const move = await askPreview(SHOWN.body, copy.failed);
    expect(request(0)).toEqual({ url: "/api/submissions/preview", method: "POST", body: { ...NAMED, publicUrl: null, text: null, contact: null } });
    const markup = view(run({ type: "asked" }, move));
    expect(markup.match(/<pre[^>]*>([^<]*)<\/pre>/)?.[1]).toBe(html(JSON.stringify(payload, null, 2)));
    for (const words of [copy.caseKey, copy.guidance, copy.permission]) expect(markup).toContain(html(words));
  });

  it("takes an https address only, and counts the text against its bound", () => {
    const http = view(run({ type: "typed", field: "publicUrl", value: "http://example.com" }, { type: "typed", field: "text", value: "abc" }));
    expect(http).toContain(html(copy.urlHttps));
    expect(button(http, copy.preview)).toContain('disabled=""');
    for (const shape of [copy.counter(3, 2000), 'maxLength="2000"']) expect(http).toContain(shape);
    expect(view(run({ type: "typed", field: "publicUrl", value: "https://example.com/app" }))).not.toContain(html(copy.urlHttps));
  });
});

describe("Send", () => {
  it("waits for a preview and permission; an edit drops both until a fresh preview of the new fields", () => {
    expect(button(view(OPENED), copy.send)).toContain('disabled=""');
    expect(canSend(run({ type: "previewed", shown: SHOWN }), SHOWN.body)).toBe(false);
    expect(canSend(ready, SHOWN.body)).toBe(true);
    expect(button(view(ready), copy.send)).not.toContain('disabled=""');
    const edited = dialog(ready, { type: "typed", field: "text", value: "Seen on every Mac." });
    const body = bodyOf(NAMED, edited.typed);
    expect(edited).toMatchObject({ shown: null, permission: false, override: false });
    expect(button(view(edited), copy.send)).toContain('disabled=""');
    const tick: Move = { type: "ticked", box: "permission", on: true };
    expect(canSend(run({ type: "previewed", shown: SHOWN }, tick), body)).toBe(false); // a preview of other fields
    expect(canSend(dialog(dialog(edited, { type: "previewed", shown: { ...SHOWN, body } }), tick), body)).toBe(true);
  });

  it("needs the separate one-time override where the exclusion list names the app, and sends it", async () => {
    expect(view(ready)).not.toContain(html(copy.override));
    const excluded: Shown = { ...SHOWN, answer: { ...SHOWN.answer, excludedBy: "org.wireshark.*" } };
    const listed = run({ type: "previewed", shown: excluded }, { type: "ticked", box: "permission", on: true });
    for (const words of [copy.excluded("org.wireshark.Wireshark", "org.wireshark.*"), copy.override]) expect(view(listed)).toContain(html(words));
    expect(canSend(listed, SHOWN.body)).toBe(false);
    expect(canSend(dialog(listed, { type: "ticked", box: "override", on: true }), SHOWN.body)).toBe(true);
    answers.push(reply(202, CASE), reply(202, CASE));
    await askSend(excluded, true, copy.failed);
    await askSend(SHOWN, true, copy.failed); // a box left ticked never overrides a list that names nothing
    const sent = { ...SHOWN.body, permission: true };
    expect([request(0), request(1)]).toMatchObject([
      { url: "/api/submissions", method: "POST", body: { ...sent, excludedOverride: true } }, { body: { ...sent, excludedOverride: false } }]);
  });

  it("sends once for a double click; a pending answer keeps Send for the retry, any later word ends it", async () => {
    const moves: Move[] = [];
    const press = oneAtATime((move) => moves.push(move));
    const lastError = "No answer came from the intelligence service at api.example.com. Check DNS, network access and INTELLIGENCE_ENDPOINT, then try again; the case keeps its key.";
    answers.push(reply(202, { ...CASE, state: "pending", lastError }));
    await Promise.all([press(() => askSend(SHOWN, false, copy.failed)), press(() => askSend(SHOWN, false, copy.failed))]);
    expect(fetchStub).toHaveBeenCalledTimes(1);
    expect(moves.map((move) => move.type)).toEqual(["asked", "sent"]);
    expect(button(view(dialog(ready, { type: "asked" })), copy.send)).toContain('disabled=""');
    const pending = moves.reduce(dialog, ready);
    expect(canSend(pending, SHOWN.body)).toBe(true);
    for (const shape of [copy.state("pending"), html(lastError), 'href="/settings/intelligence-access"']) expect(view(pending)).toContain(shape);
    const received = dialog(pending, { type: "sent", sent: CASE });
    expect(canSend(received, SHOWN.body)).toBe(false);
    expect(button(view(received), copy.send)).toBe("");
    expect(view(received)).toContain(copy.state("received"));
  });
});

describe("a refusal", () => {
  it("is the server's sentence as it came, in either language; a failure with none reads the generic line", async () => {
    answers.push(reply(409, { detail: EXCLUDED }), new Response("upstream timed out", { status: 504 }));
    const refused = await askSend(SHOWN, false, copy.failed);
    expect(refused).toEqual({ type: "refused", error: EXCLUDED });
    for (const t of [en, de]) expect(view(dialog(ready, refused), t)).toContain(`<p role="alert" class="text-sm text-destructive">${html(EXCLUDED)}</p>`);
    expect(await askPreview(SHOWN.body, copy.failed)).toEqual({ type: "refused", error: copy.failed });
    expect(await askPreview(SHOWN.body, de.submissions.failed)).toEqual({ type: "refused", error: de.submissions.failed });
  });
});

describe("Request coverage on the Vulnerabilities page", () => {
  it("offers an unknown_app build to an administrator while the preview is on, naming that build's strings only", async () => {
    expect(NAMED).toEqual({ kind: "coverage", appName: "Wireshark", bundleId: PAYLOAD.bundle_id, platform: "macos", versions: PAYLOAD.versions });
    expect(coverageFor({ ...ROW, shortVersion: "3.6.2", bundleId: "" }, true, true)).toMatchObject({ versions: ["3.6.2"], bundleId: null });
    const action = renderToStaticMarkup(<RequestCoverage entry={ROW} canWrite enabled t={en} />);
    expect(action).toContain(copy.notAssessed);
    expect(button(action, copy.requestCoverage)).not.toBe("");
    answers.push(reply(200, { enabled: true, cases: [] }), reply(200, CASE), reply(200, CASE));
    await Promise.all([listSubmissions(), submissionStatus(CASE.id), withdrawSubmission(CASE.id)]);
    expect([0, 1, 2].map((call) => `${request(call).method} ${request(call).url}`)).toEqual(
      ["GET /api/submissions", `POST /api/submissions/${CASE.id}/status`, `POST /api/submissions/${CASE.id}/withdraw`]);
  });

  it("is absent for a viewer, with the preview off, on covered and off rows, and where the service could take no case", () => {
    const refused: [CatalogEntry, boolean, boolean][] = [[ROW, false, true], [ROW, true, false], [{ ...ROW, vuln: { assessment: "off" } }, true, true],
      [{ ...ROW, vuln: { assessment: "covered" } as CatalogEntry["vuln"] }, true, true], [{ ...ROW, platform: "watchos" }, true, true],
      [{ ...ROW, version: "", shortVersion: null }, true, true]];
    for (const [entry, canWrite, enabled] of refused) {
      expect(coverageFor(entry, canWrite, enabled)).toBeNull();
      expect(renderToStaticMarkup(<RequestCoverage entry={entry} canWrite={canWrite} enabled={enabled} t={en} />)).toBe("");
    }
  });
});
