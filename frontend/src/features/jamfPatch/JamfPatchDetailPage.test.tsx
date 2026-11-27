// @vitest-environment jsdom
/** The Jamf Patch title page's dates beside a build's verdict: in the page's language, never the browser's. `./api`'s read is stubbed. */
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { JamfPatchDetailPage } from "@/features/jamfPatch/JamfPatchDetailPage";
import type { JamfPatchTitleDetail } from "@/features/jamfPatch/types";
import { de } from "@/i18n/de";
import { en } from "@/i18n/en";

const locale = vi.hoisted(() => ({ current: "en" as "en" | "de" }));
vi.mock("@/i18n/LocaleContext", async () => ({ useLocale: () => ({ locale: locale.current, t: locale.current === "de" ? de : en }) }));
const api = vi.hoisted(() => ({ getJamfPatchTitle: vi.fn() }));
vi.mock("@/features/jamfPatch/api", async original => ({ ...await original<typeof import("@/features/jamfPatch/api")>(), ...api }));
vi.mock("@/features/auth/store", () => ({ useHasPermission: () => false }));

// 2.0 listed on 11 October; 1.0 went out of policy by the 30-day limit on 10 November. Noon UTC, so every zone reads the same day.
const title: JamfPatchTitleDetail = { id: "0AB", name: "Example App", publisher: "Example", appName: "Example App.app", appNameSource: "jamf",
  bundleId: "com.example.app", currentVersion: "2.0", lastModified: "2026-10-11T12:00:00Z", syncedAt: "2026-11-25T12:00:00Z", deviceCount: 3,
  devicesOnLatest: 1, devicesBehind: 2, devicesOutOfPolicy: 2, policySource: "default",
  patches: [{ version: "2.0", releaseDate: "2026-10-11T12:00:00Z" }, { version: "1.0", releaseDate: "2026-08-03T12:00:00Z" }],
  requirements: [], extensionAttributes: null, versionDeviceCounts: { "2.0": 1, "1.0": 2 }, versionVulns: {}, corpusAsOf: null,
  policy: { maxDaysBehind: 30, maxReleasesBehind: null, maxDaysBehindSevere: null, source: "default", exempt: false, severityAnswering: null, versions: {
    "2.0": { state: "within", reason: null, since: null, daysBehind: null, releasesBehind: 0, limitDays: 30, severe: null },
    "1.0": { state: "out", reason: "days", since: "2026-11-10T12:00:00Z", daysBehind: 45, releasesBehind: 1, limitDays: 30, severe: null } } } };

beforeEach(() => { vi.clearAllMocks(); api.getJamfPatchTitle.mockResolvedValue(title); locale.current = "en"; });
afterEach(cleanup);

async function open() {
  render(<MemoryRouter initialEntries={["/devices/applications/jamf-patch/0AB"]}><Routes>
    <Route path="/devices/applications/jamf-patch/:titleId" element={<JamfPatchDetailPage />} /></Routes></MemoryRouter>);
  expect(await screen.findByRole("heading", { name: title.name })).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: (locale.current === "de" ? de : en).jamfPatch.detail.versionsTitle }));
  return within(screen.getByRole("table")).getAllByRole("row").slice(1).map(row => [...(row as HTMLTableRowElement).cells].map(cell => cell.textContent));
}

it("dates a build out by its days limit in German, in its table row and its chart tooltip alike", async () => {
  locale.current = "de";
  const sentence = "Außerhalb der Richtlinie seit 10.11.2026: eine neuere Version ist seit 45 Tagen geführt (Grenze 30)";
  expect(await open()).toEqual([["2.0", "11.10.2026", "1", de.jamfPatch.rules.verdictWithin], ["1.0", "3.8.2026", "2", sentence]]);
  expect(screen.getByText(`1.0: 2 Geräte · veröffentlicht 3.8.2026 · ${sentence}`)).toBeTruthy();
});

it("dates the same row in English on an English page", async () => {
  const sentence = "Out of policy since 11/10/2026: a newer release has been listed for 45 days (limit 30)";
  expect(await open()).toEqual([["2.0", "10/11/2026", "1", en.jamfPatch.rules.verdictWithin], ["1.0", "8/3/2026", "2", sentence]]);
  expect(screen.getByText(`1.0: 2 devices · released 8/3/2026 · ${sentence}`)).toBeTruthy();
});
