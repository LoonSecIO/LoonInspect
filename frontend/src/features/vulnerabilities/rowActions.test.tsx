/** The submission actions in the Vulnerabilities rows (#623, #686): Request coverage and Report an incorrect match sit
 *  in their rows for an administrator while the v2 preview is on and nowhere else, and each list hands its rows its
 *  OWN release. Node lane (#285): the page's two gates are read where the page reads them, stubbed at their sources
 *  as SubmissionCases.test.tsx stubs the permission. */

import { describe, expect, it, vi } from "vitest";
import type { ReactElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router";
import { PERMISSIONS } from "@/features/auth/types";
import type { CatalogEntry, CatalogListResponse } from "@/features/catalog/types";
import { ListRows } from "@/features/vulnerabilities/VulnerabilitiesPage";
import { en } from "@/i18n/en";

const reader = vi.hoisted(() => ({ grants: [] as string[], preview: false }));
vi.mock("@/features/auth/store", async (importOriginal) => ({ ...(await importOriginal<typeof import("@/features/auth/store")>()),
  useHasPermission: (permission: string) => reader.grants.includes(permission) }));
vi.mock("@/features/system/intelligenceStore", async (importOriginal) => ({ ...(await importOriginal<typeof import("@/features/system/intelligenceStore")>()),
  useIntelligenceStore: <T,>(select: (state: { enabled: boolean }) => T) => select({ enabled: reader.preview }) }));

const copy = en.submissions;
const ADMIN: string[] = [PERMISSIONS.SYSTEM_READ, PERMISSIONS.SYSTEM_WRITE];
const VIEWER: string[] = [PERMISSIONS.SYSTEM_READ];
const [MOST_EXPOSED, PATCHABLE] = ["1a2b".repeat(16), "9e8d".repeat(16)]; // two lists, two manifest signatures
const BUILD: Omit<CatalogEntry, "id" | "name" | "vuln"> = { bundleId: "org.example.app", version: "4.2.0", shortVersion: null, platform: "macos",
  appHash: "a1", versionHash: "v1", keyTitle: "", keyFull: "", firstSeenAt: "2026-09-01T00:00:00Z", lastSeenAt: "2026-09-20T00:00:00Z", deviceCount: 3,
  jamfTitleIds: null, jamfTitles: [], patchState: null, isLatest: null, patchAvailable: null, patchAvailableSince: null, releasesMissed: null,
  thisVersionSeen: null, latestVersion: null, latestReleasedAt: null, eaAssumed: null, referenceTitleId: null, sentenceTitleId: null,
  releasedAt: null, evaluatedAt: null, evaluatedSignature: null, vulnUpdate: null, seenHereDays: null };
const UNKNOWN: CatalogEntry = { ...BUILD, id: 1, name: "Wireshark", vuln: { assessment: "unknown_app", corpusAsOf: "2026-09-20" } };
const COVERED: CatalogEntry = { ...BUILD, id: 2, name: "Firefox", vuln: { assessment: "covered", corpusAsOf: "2026-09-20",
  counts: { total: 2, kev: 1, severity: { critical: 1, high: 1, medium: 0, low: 0 } },
  daysOldestPublished: { total: 40, severity: { critical: 40, high: 12, medium: null, low: null } }, vulnIDs: ["CVE-2024-0001", "CVE-2024-0002"], vulnIDsTruncated: false } };
const list = (items: CatalogEntry[], corpusRelease: string | null): CatalogListResponse =>
  ({ items, total: items.length, page: 1, pageSize: 10, summary: null, corpusAsOf: "2026-09-20", corpusRelease, vulnJudged: true });

/** One list as the page draws it, for this reader; `ranked` is *Easily patchable*'s. */
function drawn(listed: CatalogListResponse, ranked: boolean, grants: string[], preview: boolean) {
  Object.assign(reader, { grants, preview });
  return renderToStaticMarkup(<MemoryRouter><table><tbody><ListRows list={listed} ranked={ranked} t={en} /></tbody></table></MemoryRouter>);
}
const offered = (markup: string) => ({ coverage: markup.split(`>${copy.requestCoverage}</button>`).length - 1, report: markup.split(`>${copy.reportMatch}</button>`).length - 1 });
/** What the list hands each row, read off the elements it returns: this lane has no DOM to open a dialog in. */
function handed(listed: CatalogListResponse, ranked: boolean, grants: string[], preview: boolean) {
  Object.assign(reader, { grants, preview });
  return (ListRows({ list: listed, ranked, t: en }) as ReactElement<{ canWrite: boolean; enabled: boolean; release: string | null }>[])
    .map(({ props: { canWrite, enabled, release } }) => ({ canWrite, enabled, release }));
}

describe("the submission actions in the Vulnerabilities rows", () => {
  it("are offered to an administrator with the preview on: both in Most exposed, the report in Easily patchable", () => {
    expect(offered(drawn(list([UNKNOWN, COVERED], MOST_EXPOSED), false, ADMIN, true))).toEqual({ coverage: 1, report: 1 });
    expect(offered(drawn(list([COVERED], PATCHABLE), true, ADMIN, true))).toEqual({ coverage: 0, report: 1 });
  });

  it("are absent for a viewer and with the preview off, from rows that are still drawn", () => {
    for (const [grants, preview] of [[VIEWER, true], [ADMIN, false], [VIEWER, false]] as const) {
      for (const ranked of [false, true]) {
        const markup = drawn(list([UNKNOWN, COVERED], MOST_EXPOSED), ranked, grants, preview);
        expect([markup.includes(">Wireshark 4.2.0</a>"), markup.includes(">Firefox 4.2.0</a>")]).toEqual([true, true]);
        expect(offered(markup)).toEqual({ coverage: 0, report: 0 });
      }
      expect(handed(list([COVERED], PATCHABLE), true, grants, preview)).toEqual([{ canWrite: grants === ADMIN, enabled: preview, release: PATCHABLE }]);
    }
  });

  it("name the release of the list they sit in, so Easily patchable hands on its own and a list without one offers no report", () => {
    expect(handed(list([UNKNOWN, COVERED], MOST_EXPOSED), false, ADMIN, true).map((acts) => acts.release)).toEqual([MOST_EXPOSED, MOST_EXPOSED]);
    expect(handed(list([COVERED], PATCHABLE), true, ADMIN, true)).toEqual([{ canWrite: true, enabled: true, release: PATCHABLE }]);
    for (const ranked of [false, true]) expect(offered(drawn(list([COVERED], null), ranked, ADMIN, true)).report).toBe(0);
  });
});
