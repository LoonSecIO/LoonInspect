import { SLIDER_STOPS, type SliderStop } from "@/features/patchPolicy/replay";
import type { PatchPolicyWalk, WalkPolicy, WalkSource } from "@/features/patchPolicy/walk";
import type { PatchPolicyApp, PatchPolicyAppsResponse, PatchPolicyFeed, PatchPolicySource, PatchPolicySourceTrack } from "@/features/support/patchPolicyFeed";

/**
 * Hand-made day-walk answers for the patch-policy page's tests (#614), and nothing else: no module the
 * app loads imports this one. Every value is invented: the CVE ids are in 2099, the digests say
 * `fixture`, and the window is ten days of January 2025, so nothing here reads as a finding about a
 * real app. The walks themselves are the instance's (`app.core.patch_policy_walk`), held to their
 * own invariants there; these only have to be the shape the page draws. Each call returns a fresh copy.
 */

const SINCE = "2025-01-01";
const UNTIL = "2025-01-10";
const DAYS = 10;

const zeros = () => Array.from({ length: DAYS }, () => 0);

/** The instance's sentence for a matched check: one check serves every source and aligned window
 *  of the track, so it names the public walk it is of. */
export const CHECK_DETAIL = "The walk of LoonSec's published dates for Example 4.4 over 2 years matches the totals LoonSec published with the data.";

/** One stop's totals and series. Each stop opens one CVE carried in, opens another on day 6, and
 *  resolves them on installs that come later the slower the stop. */
function policy(stop: SliderStop, delay: number | null): WalkPolicy {
  const never = delay === null;
  const firstFix = never ? null : Math.min(DAYS - 1, 3 + Math.floor(delay / 10));
  const secondFix = never ? null : Math.min(DAYS - 1, 8 + Math.floor(delay / 30));
  const open = zeros();
  const fresh = zeros();
  const resolved = zeros();
  for (let day = 0; day < DAYS; day += 1) {
    open[day] = (firstFix === null || day < firstFix ? 1 : 0) + (day >= 5 && (secondFix === null || day < secondFix) ? 1 : 0);
  }
  fresh[5] = 1;
  if (firstFix !== null) resolved[firstFix] += 1;
  if (secondFix !== null && secondFix > 5) resolved[secondFix] += 1;
  const installs = never
    ? []
    : [
        { date: `2025-01-${String(firstFix! + 1).padStart(2, "0")}`, version: "4.4.2" },
        { date: `2025-01-${String(secondFix! + 1).padStart(2, "0")}`, version: "4.4.3" }
      ].filter((each, index, all) => all.findIndex((other) => other.date === each.date) === index);
  const neverSeen = { "1d": 2, "7d": 2, "14d": 1, "30d": 1, "60d": 1, never: 0 }[stop];
  return {
    stop,
    install_delay_days: delay,
    never_seen: neverSeen,
    never_seen_outside_affected_range: neverSeen > 0 ? 1 : 0,
    exposed: 3 - neverSeen,
    exposure_days: (3 - neverSeen) * 4,
    carried_in: 1,
    entered_after_start: 0,
    pre_window_closed: 0,
    exposure_days_carried_in: firstFix ?? DAYS,
    exposure_days_entered_after_start: 0,
    open_at_window_end: { in_window: open[DAYS - 1] > 0 ? 1 : 0, carried_in: never ? 1 : 0, entered_after_start: 0 },
    update_events: installs.length,
    initial_version: "4.4.1",
    final_version: never ? "4.4.1" : "4.4.3",
    installs,
    series: {
      opening: 1,
      open,
      new: fresh,
      resolved,
      new_by_reason: { became_detectable: fresh.slice(), entered_range: zeros() },
      resolved_by_reason: { update_installed: resolved.slice() }
    }
  };
}

const DELAYS: Record<SliderStop, number | null> = { "1d": 0, "7d": 6, "14d": 13, "30d": 29, "60d": 59, never: null };

export function walkFixture(overrides: Partial<PatchPolicyWalk> & { source?: WalkSource } = {}): PatchPolicyWalk {
  const { source = "public", ...rest } = overrides;
  const names: Record<WalkSource, string> = {
    public: "Example release tags (fixture)",
    jamf: "this instance's copy of Jamf's public patch catalog (Example, Example 4.4)",
    fleet: "this instance's Fleet history (example-app)"
  };
  const outcome = (stop: SliderStop) =>
    stop === "never" || stop === "60d"
      ? { class: "in_window" as const, outcome: "exposed" as const, exposure_days: 5, open_at_window_end: true, cleared_on: null, cleared_by: null, version_at_clock: "4.4.1" }
      : { class: "in_window" as const, outcome: "exposed" as const, exposure_days: 3, open_at_window_end: false, cleared_on: "2025-01-09", cleared_by: "4.4.3", version_at_clock: "4.4.2" };
  return {
    kind: "patch_policy_walk",
    schema: 1,
    algorithm: "patch_walk/1",
    definitions_version: "2",
    input_id: "fixture-input-0001",
    run_id: "fixture-run-0001",
    inputs: {
      doc_id: "fixture-doc-0001",
      doc_as_of: "2025-01-11T20:00:00Z",
      app: "example",
      name: "Example",
      track: "example/4.4",
      label: "Example 4.4",
      path: { kind: "hold", ceiling_line: "4.4", waits_for_promotion: false },
      timeline: {
        source,
        name: names[source],
        digest: "fixture-digest-timeline",
        as_of: "2025-01-11",
        first: "2024-10-01",
        last: "2025-01-09",
        observations: 4,
        matched: 4,
        unmatched: [],
        other_track: 0,
        undated: 0,
        conflicts: 0,
        in_reach: { since: "2024-11-02", until: UNTIL, matched: 3, unmatched: [], share: 0 },
        ids: [source === "public" ? "example-tags" : source === "jamf" ? "0X1" : "example-app"],
        other_track_versions: [],
        note: source === "fleet" ? "These are Fleet's dates, not the vendor's (fixture note)." : null
      }
    },
    window: { requested: { years: 2, since: SINCE, until: UNTIL }, since: SINCE, until: UNTIL, days: DAYS, shortened_by: [] },
    counts: {
      cves_in_doc: 6,
      in_window: 4,
      replayed: 3,
      excluded: 1,
      before_window: 1,
      before_window_excluded: 0,
      after_window: 1,
      without_clock: 0,
      not_detectable: 2,
      uncertain_over_1d: 0,
      replayed_by_clock: { detectable_at: 2, published: 1 },
      placed_by_clock: { detectable_at: 3, published: 3 }
    },
    exclusions: {
      by_reason: { rejected: 0, no_configuration_for_pair: 1, branch_ambiguity: 0 },
      cves: [{ cve_id: "CVE-2099-0009", reason: "no_configuration_for_pair", clock: "published", clock_date: "2025-01-07", published: "2025-01-07", detail: null }],
      before_window_by_reason: {}
    },
    policies: Object.fromEntries(SLIDER_STOPS.map((stop) => [stop, policy(stop, DELAYS[stop])])) as Record<SliderStop, WalkPolicy>,
    cves: [
      {
        cve_id: "CVE-2099-0001",
        class: "in_window",
        clock: "detectable_at",
        clock_date: "2025-01-06",
        published: "2025-01-04",
        detectable_at: "2025-01-06",
        severity: "high",
        kev_date_added: "2025-01-08",
        outcomes: Object.fromEntries(SLIDER_STOPS.map((stop) => [stop, outcome(stop)]))
      },
      {
        cve_id: "CVE-2099-0002",
        class: "in_window",
        clock: "published",
        clock_date: "2025-01-02",
        published: "2025-01-02",
        detectable_at: null,
        severity: null,
        kev_date_added: null,
        outcomes: Object.fromEntries(SLIDER_STOPS.map((stop) => [stop, { class: "in_window", outcome: "never_seen", why: "fix_installed_first" }]))
      },
      {
        cve_id: "CVE-2099-0003",
        class: "before_window",
        clock: "detectable_at",
        clock_date: "2024-12-20",
        published: "2024-12-19",
        detectable_at: "2024-12-20",
        severity: "medium",
        kev_date_added: null,
        outcomes: Object.fromEntries(
          SLIDER_STOPS.map((stop) => [stop, { class: "carried_in", outcome: "exposed", exposure_days: 3, open_at_window_end: false, cleared_on: "2025-01-04", cleared_by: "4.4.2" }])
        )
      }
    ],
    cves_page: { page: 1, page_size: 200, pages: 1, total: 3 },
    intervals_for: null,
    check: { state: "matched", detail: CHECK_DETAIL },
    definitions: { cve_clock: "A CVE is placed by the first day it was detectable (fixture definition)." },
    document_definitions: {},
    clocks: { published: "NVD publication (fixture clock)." },
    ...rest
  };
}

const sourceTrack = (track: string, state = "available", sentence: string | null = null): PatchPolicySourceTrack => ({
  track,
  available: state === "available",
  state,
  sentence,
  first: state === "available" ? "2024-10-01" : null,
  last: state === "available" ? "2025-01-09" : null,
  matched: state === "available" ? 4 : 0,
  otherTrack: 0,
  unmatched: 0,
  since: state === "available" ? SINCE : null,
  until: state === "available" ? UNTIL : null
});

const source = (tracks: PatchPolicySourceTrack[], note: string | null = null): PatchPolicySource => ({
  available: tracks.some((each) => each.available),
  state: tracks.some((each) => each.available) ? "available" : (tracks[0]?.state ?? ""),
  first: null,
  last: null,
  sentence: tracks.some((each) => each.available) ? null : (tracks[0]?.sentence ?? null),
  ids: [],
  matched: 0,
  asOf: null,
  note,
  tracks
});

export const NO_TITLE_SENTENCE =
  "This instance's copy of Jamf's public patch catalog has no title for Example (bundle id com.example.app), so there are no Jamf dates to walk. Devices › Applications › Jamf Patch lists the titles it holds; choose another source.";
export const FLAG_OFF_SENTENCE =
  "Fleet's catalog is not read while the Fleet catalog flag is off for this organization. Turn on “Fleet catalog (maintained apps)” under Settings › Feature Flags, then check again.";

/** One app with two tracks: Public dates both, Jamf has no title, Fleet's flag is off. */
export function appFixture(overrides: Partial<PatchPolicyApp> = {}): PatchPolicyApp {
  const tracks = ["example/4.4", "example/newest"];
  const track = (id: string, label: string, isDefault: boolean) => ({
    track: id,
    label,
    default: isDefault,
    channel: "release",
    edition: "release",
    timeline: "example-tags",
    versions: 6,
    versionsDated: 6,
    candidates: 6,
    listed: 3,
    excluded: 1,
    notDetectable: 2,
    clock: { detectableAt: 2, published: 1 }
  });
  return {
    app: "example",
    name: "Example",
    bundleIds: ["com.example.app"],
    tracks: [track("example/4.4", "Example 4.4", true), track("example/newest", "Example (newest line)", false)],
    sources: {
      public: source(tracks.map((id) => sourceTrack(id))),
      jamf: source(tracks.map((id) => sourceTrack(id, "no_title", NO_TITLE_SENTENCE))),
      fleet: source(tracks.map((id) => sourceTrack(id, "flag_off", FLAG_OFF_SENTENCE)))
    },
    ...overrides
  };
}

/** Every source available on every track. */
export function openApp(): PatchPolicyApp {
  const app = appFixture();
  const all = source(app.tracks.map((each) => sourceTrack(each.track)));
  return { ...app, sources: { public: all, jamf: all, fleet: all } };
}

export function feedFixture(overrides: Partial<PatchPolicyFeed> = {}): PatchPolicyFeed {
  return {
    state: "current",
    sentence: "",
    algorithm: "patch_walk/1",
    docId: "fixture-doc-0001",
    asOf: "2025-01-11T20:00:00Z",
    fetchedAt: "2025-01-11T21:00:00Z",
    coverageSince: "2024-05-21",
    until: UNTIL,
    attemptedAt: "2025-01-11T21:00:00Z",
    source: "exchange",
    outcome: "stored",
    host: null,
    httpStatus: null,
    detail: null,
    fromFile: false,
    builtAt: "2025-01-11T20:30:00Z",
    ...overrides
  };
}

export function appsFixture(apps: PatchPolicyApp[] | null = [appFixture()], feed: Partial<PatchPolicyFeed> = {}): PatchPolicyAppsResponse {
  return { feed: feedFixture(feed), apps };
}
