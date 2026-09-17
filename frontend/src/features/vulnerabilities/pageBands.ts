import { PERMISSIONS } from "@/features/auth/types";
import { findingIdIn } from "@/features/vulnerabilities/findingId";
import type { AppVulnerability } from "@/features/vulnerabilities/types";

/** The decisions Posture › Vulnerabilities makes before drawing its extra bands (#538), as
 *  functions, so the frontend test lane holds them without rendering anything (#285). Each is a
 *  ruling and not a layout; what each one rules is said where it is defined. */

/** Only what the grouping reads; a `CatalogEntry` satisfies it, so a test needs no other column. */
export interface AffectedRow {
  name: string;
  deviceCount: number;
  vuln: AppVulnerability;
}

/** An *Explore by app* chip. The name is the whole chip: pressing it puts exactly this string in
 *  `q`. `rank` is affected Macs summed over that app's affected builds IN HAND — a ranking key and
 *  never a printed number, since a Mac on two builds of one app is counted twice and no honest
 *  fleet-wide device count is available per request (§4g). */
export interface AppChip {
  name: string;
  rank: number;
}

/** The apps carrying the most affected Macs — Kyle's eight, 2026-09-17 — grouped **client-side**
 *  from the rows already in hand, the first page of *Most exposed*: no second request and no
 *  tenant-wide aggregate. Grouped by NAME and not by `appHash`, because the name is what the chip
 *  searches for, so two records sharing one are one chip and exactly the set `q` brings back. A
 *  build with no finding ranks nothing: `counts` lives only inside the `covered` narrowing. */
export function exploreByApp(rows: readonly AffectedRow[], limit = 8): AppChip[] {
  const ranked = new Map<string, number>();
  for (const row of rows) {
    if (row.vuln.assessment !== "covered" || row.vuln.counts.total === 0) continue;
    ranked.set(row.name, (ranked.get(row.name) ?? 0) + row.deviceCount);
  }
  return [...ranked]
    .map(([name, rank]) => ({ name, rank }))
    .sort((left, right) => right.rank - left.rank || left.name.localeCompare(right.name))
    .slice(0, limit);
}

/** Whether the list on screen IS *Longest exposed*: the age ordering and the words for it hold only
 *  over the builds with findings, so any other filter — pressed, or reached with **Back**, which moves
 *  the address without passing the chip handler — is *Most exposed* again. Derived and never stored,
 *  so heading, hint and the `order` asked for cannot disagree about which list this is. */
export const agedList = (expanded: boolean, order: string, vuln: string, band: string | null): boolean => expanded && order === "age" && vuln === "findings" && band === null;

/** Whether the list on screen IS *Easily patchable*: the ranking is the half that makes the filter
 *  an answer, so the two are one state and not two. Read off the filter alone rather than off
 *  `order=payoff` beside it — the chip still writes both, but an address typed or forwarded without
 *  the order was headed *Most exposed* and then printed the band again below it, the same rows twice
 *  under two headings. `agedList`'s instinct: heading, hint, columns and the order asked for cannot
 *  disagree about which list this is, because one value decides all four. */
export const payoffList = (vuln: string): boolean => vuln === "patchable";

/** Which sentence an empty table says: one key of `t.vulnerabilities`, chosen from the WHOLE
 *  narrowing and never from part of it. `docs/diagnosability.md` rule 1 — *no match for this
 *  search*, *this filter has nothing* and *the fleet carries nothing* are different states, and one
 *  blank standing for all of them has hidden the other two.
 *
 *  The defect this replaces: `jamf` arrived as a third narrowing dimension beside `vuln` and `band`
 *  (#532) and was left out of the sentence, so *No Jamf fix path* on a fleet where every build with
 *  findings HAS a Patch title printed *no build the fleet carries has a finding against it in this
 *  corpus* — a fleet-wide claim, false, printed directly under *Most exposed* listing the builds it
 *  denied. The good news the chip exists to surface read as the bad news it disproves.
 *
 *  So every narrowing answers for itself and only the unnarrowed list may speak for the fleet. The
 *  search is asked first because it is the narrowing the reader performed last, and a chip's own
 *  sentence is a claim about that chip's whole set — any further narrowing beside it and the honest
 *  answer is *this filter*, not the claim.
 *
 *  `search` is an `AppliedSearch` and not any string: the lane is node-only and cannot render
 *  the call site, so the type holds what a test cannot reach. */
export function emptySays(vuln: string, band: string | null, jamf: string | null, search: AppliedSearch): EmptySays {
  const narrowed = vuln !== "findings" || band !== null || jamf !== null;
  if (search.trim() !== "") return narrowed ? "noRows" : "noMatches";
  if (jamf !== null) return vuln === "findings" && band === null ? "noFixPathNone" : "noRows";
  if (vuln === "patchable" && band === null) return "easilyPatchableNone";
  return narrowed ? "noRows" : "noFindings";
}

export type EmptySays = "noMatches" | "noRows" | "noFixPathNone" | "easilyPatchableNone" | "noFindings";

/** The `q` a request RAN with, as against the text sitting in the box. Only `listQuery` mints one,
 *  so nothing can explain a list by a search that was never sent. */
export type AppliedSearch = string & { readonly __applied: "search" };

/** The one `q` the page asks with, so that everything explaining the result reads the same value.
 *  Lever off, that is the box. Lever on, the box holds a QUESTION and the search is the applied
 *  answer's `q` — usually none at all. An id is neither: it is routed on Enter (#533) and was
 *  never a filter, so no request runs with one.
 *
 *  The defect (#534): the empty table chose its sentence from the BOX, so an applied
 *  `vuln=findings` with *do we have anything at all?* still typed printed *No build with findings
 *  matches that search* for a search that never ran, and the fleet's own sentence was unreachable
 *  — the conflation `docs/diagnosability.md` rule 1 forbids. Two consumers deriving one value
 *  separately is how that happened, so here it is derived once. */
export function listQuery(asks: boolean, term: string, askedFor: string): AppliedSearch {
  const value = asks ? askedFor : term;
  return (findingIdIn(value) ? "" : value) as AppliedSearch;
}

/** The four `vuln.*` keys of the nightly tape, in the order the foot prints them. Read, never
 *  written, and no key is minted here (`docs/posture-snapshot.md`, §7). */
export const VULN_KEYS = ["vuln.apps_affected", "vuln.apps_kev_affected", "vuln.apps_unknown", "vuln.devices_affected"] as const;

export type VulnKey = (typeof VULN_KEYS)[number];

/** One row of `GET /api/posture`; `fullSweepRunId` is null once the run is purged at 30 days. */
export interface PostureRow {
  key: string;
  value: number;
  capturedAt: string;
  fullSweepRunId: string | null;
}

/** Whether the foot's *By the numbers* tile is planned at all — `overviewPlan.ts`'s rule (#115):
 *  every tile is planned against the permission its own source demands, so none is rendered into a
 *  403. `GET /api/posture` is `audit:read`-gated and a viewer-role account does not hold it, so
 *  that account is shown the lists and no tile rather than an error. There is deliberately no
 *  second read of the tape under another permission to give it one — #470's ruling to reopen. */
export function planNumbers(permissions: readonly string[]): boolean {
  return permissions.includes(PERMISSIONS.AUDIT_READ);
}

export interface NumbersRead {
  /** The capture those rows came from, or `null` when it wrote none of the four. */
  capturedAt: string | null;
  runId: string | null;
  present: { key: VulnKey; value: number }[];
  /** The keys with no row. Printed as an absence and **never** as a zero. */
  absent: VulnKey[];
}

/** The latest capture's four rows, read as rows (#470). A key with no row is *absent*, a statement
 *  about that night and not the number nought: nothing here defaults, sums or fills a gap. The four
 *  are written only once a corpus has judged the tenant, so an empty read is an ordinary first. */
export function readNumbers(rows: readonly PostureRow[]): NumbersRead {
  const found = VULN_KEYS.map((key) => ({ key, row: rows.find((row) => row.key === key) ?? null }));
  const stamp = found.find((entry) => entry.row !== null)?.row ?? null;
  return {
    capturedAt: stamp?.capturedAt ?? null,
    runId: stamp?.fullSweepRunId ?? null,
    present: found.flatMap(({ key, row }) => (row ? [{ key, value: Math.round(row.value) }] : [])),
    absent: found.flatMap(({ key, row }) => (row ? [] : [key]))
  };
}
