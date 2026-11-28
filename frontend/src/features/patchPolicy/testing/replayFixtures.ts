/**
 * Hand-made schema-3 replay files for the patch-policy tests (#614, #953), and nothing else: no module
 * the app loads imports this one, so it never reaches the build. Two shapes the page must draw:
 *
 * - `heldLineReplay`: an app with several release lines, held on `4.4` (`branch_components` 2).
 * - `singleLineReplay`: an app replayed as one line (`branch_components` 0): `held_at_branch` is
 *   `null` and every fix is on the line `""`. Its device waits for a major's promotion day (`skip`).
 *
 * Both count the days waited, as schema 3 does (ruled 2026-11-27, "0 = same day"): a stop of D days
 * installs each release D days after its date on the file's timeline, and each day row says so in
 * `install_delay_days`. Every number below is derived by hand from the release dates in the
 * comment above each file, on that rule.
 *
 * Every value is invented. The CVE ids are in 2099, the timelines are on example.com and the run ids
 * say `fixture`, so nothing here can be read as a finding about a real app, nor as a replay of one.
 * The replays the page ships are LoonVD's files under `../replays/`, and `../replays/README.md` names
 * their sources. The totals close, so `readReplay` accepts both as they stand; each call returns a
 * fresh copy.
 */

type Outcome = Record<string, unknown>;

const fixFirst: Outcome = { outcome: "never_seen", why: "fix_installed_first" };
const outside: Outcome = { outcome: "never_seen", why: "outside_affected_range" };
const cleared = (days: number, by: string, on: string): Outcome => ({
  outcome: "exposed",
  exposure_days: days,
  cleared_by: by,
  cleared_on: on,
  open_at_window_end: false
});
const open = (days: number): Outcome => ({ outcome: "exposed", exposure_days: days, cleared_by: null, cleared_on: null, open_at_window_end: true });

/** One policy row. `delay` is the days a day row waits (`install_delay_days`): null for Never, and
 *  absent for the superseded `critical_or_kev` row, which is no stop. */
const policy = (
  delay: number | null | undefined,
  never_seen: number,
  never_seen_outside_affected_range: number,
  exposed: number,
  exposure_days: number,
  open_at_window_end: number,
  initial_version: string,
  installs: { date: string; version: string }[]
) => ({
  ...(delay !== undefined && { install_delay_days: delay }),
  path: "hold",
  never_seen,
  never_seen_outside_affected_range,
  exposed,
  exposure_days,
  open_at_window_end,
  update_events: installs.length,
  initial_version,
  final_version: installs.at(-1)?.version ?? initial_version,
  installs
});

const installs = (pairs: [string, string][]) => pairs.map(([date, version]) => ({ date, version }));

const reasons = (counts: Record<string, number>) => ({
  rejected: 0,
  no_configuration_for_pair: 0,
  excluded_platform: 0,
  configuration_declined: 0,
  only_prerelease_criteria: 0,
  no_fixed_version_determinable: 0,
  fixed_version_not_in_catalog: 0,
  branch_ambiguity: 0,
  ...counts
});

const clocks = {
  published: "NVD `published`, truncated to the UTC date.",
  release_date: "The release's date on this file's timeline (`timeline`).",
  severity: "Today's score. No score history is held."
};

const install =
  "A policy of D days installs each release D days after its date on the timeline, so 0 days installs it on that date (fixture definition).";
/** The superseded row's definition, in a file's words (invented, like the rest). */
const superseded =
  "Superseded by the ruled policy definitions: do not quote this row. As computed, a release is installed on the first day a CVE it fixes is KEV-listed or critical (fixture definition).";

/** Example App, held on 4.4. Releases on its timeline: 4.4.2 on 2024-11-27, 4.4.3 on 2025-01-08 and
 *  4.4.4 on 2025-03-05, each installed D days after that date:
 *    0d  2024-11-27, 2025-01-08, 2025-03-05     1d  2024-11-28, 2025-01-09, 2025-03-06
 *    3d  2024-11-30, 2025-01-11, 2025-03-08     7d  2024-12-04, 2025-01-15, 2025-03-12
 *    14d 2024-12-11, 2025-01-22, 2025-03-19     30d 2024-12-27, 2025-02-07, 2025-04-04
 *    60d 2025-01-26, 2025-03-09, 2025-05-04
 *  A CVE published on or after its fix's install day is never seen (fix first); one published before
 *  it is exposed from publication to the day before the install. So:
 *    CVE-0001 (published 2024-11-28, fix 4.4.2): 0d and 1d fix first; days exposed 3d 2, 7d 6,
 *      14d 13, 30d 29, 60d 59; never 725, open (the window ends 2026-11-23, counted to the day before).
 *    CVE-0002 (its only fix on 4.6): never in range under every policy.
 *    CVE-0003 (published 2025-01-15, fix 4.4.3): 0d to 7d fix first (7d installs it that day); 14d 7,
 *      30d 23, 60d 53 days; never 677, open.
 *    CVE-0004 (published 2025-03-04, fix 4.4.4): 0d 1, 1d 2, 3d 4, 7d 8, 14d 15, 30d 31, 60d 61 days;
 *      never 629, open.
 *  Never seen along the slider: 3, 3, 2, 2, 1, 1, 1, 1; exposure days 1, 2, 6, 14, 35, 83, 173, 2031. */
export function heldLineReplay(): Record<string, unknown> {
  // Cloned whole: the shared pieces above are reused by both files, and a test edits its copy freely.
  return structuredClone({
    kind: "patch_policy_replay",
    schema: 3,
    run_id: "fixture-held-line",
    product: { key: "example:app", cpe_pairs: ["example:app"], bundle_ids: ["com.example.App"], device_bundle_id: "com.example.App" },
    window: { since: "2024-11-23", until: "2026-11-23" },
    timeline: {
      source: "example_tags",
      name: "Example App's release tags",
      url: "https://example.com/example-app/tags",
      fetched_at: "2026-11-24T09:15:42Z",
      sha256: "1111111111111111111111111111111111111111111111111111111111111111",
      clock: "The UTC date of the release's tag. Release-candidate tags are dropped."
    },
    definitions: {
      install,
      never: "The device stays on the version that was current when the window opened.",
      critical_or_kev: superseded
    },
    cve_clock: "published",
    clocks,
    evidence: { branch_components: 2, parser_version: "v1", version_compare: "v0", observer: "macos" },
    counts: { cves_considered: 9, cves_outside_window: 4, cves_without_published: 0, cves_in_window: 5, cves_replayed: 4, cves_excluded: 1 },
    exclusions: {
      by_reason: reasons({ no_configuration_for_pair: 1 }),
      cves: [{ cve_id: "CVE-2099-0005", reason: "no_configuration_for_pair", published: "2025-06-01", detail: null }]
    },
    releases: [
      { version: "4.4.2", branch: "4.4", release_date: "2024-11-27" },
      { version: "4.4.3", branch: "4.4", release_date: "2025-01-08" },
      { version: "4.4.4", branch: "4.4", release_date: "2025-03-05" }
    ],
    policies: {
      "0d": policy(0, 3, 1, 1, 1, 0, "4.4.1", installs([["2024-11-27", "4.4.2"], ["2025-01-08", "4.4.3"], ["2025-03-05", "4.4.4"]])),
      "1d": policy(1, 3, 1, 1, 2, 0, "4.4.1", installs([["2024-11-28", "4.4.2"], ["2025-01-09", "4.4.3"], ["2025-03-06", "4.4.4"]])),
      "3d": policy(3, 2, 1, 2, 2 + 4, 0, "4.4.1", installs([["2024-11-30", "4.4.2"], ["2025-01-11", "4.4.3"], ["2025-03-08", "4.4.4"]])),
      "7d": policy(7, 2, 1, 2, 6 + 8, 0, "4.4.1", installs([["2024-12-04", "4.4.2"], ["2025-01-15", "4.4.3"], ["2025-03-12", "4.4.4"]])),
      "14d": policy(14, 1, 1, 3, 13 + 7 + 15, 0, "4.4.1", installs([["2024-12-11", "4.4.2"], ["2025-01-22", "4.4.3"], ["2025-03-19", "4.4.4"]])),
      "30d": policy(30, 1, 1, 3, 29 + 23 + 31, 0, "4.4.1", installs([["2024-12-27", "4.4.2"], ["2025-02-07", "4.4.3"], ["2025-04-04", "4.4.4"]])),
      "60d": policy(60, 1, 1, 3, 59 + 53 + 61, 0, "4.4.1", installs([["2025-01-26", "4.4.2"], ["2025-03-09", "4.4.3"], ["2025-05-04", "4.4.4"]])),
      never: policy(null, 1, 1, 3, 725 + 677 + 629, 3, "4.4.1", []),
      critical_or_kev: policy(undefined, 1, 1, 3, 147, 0, "4.4.1", installs([["2025-03-05", "4.4.4"]]))
    },
    branch_choice: {
      default_path: "hold",
      alternative_path: "latest",
      held_at_branch: "4.4",
      cves_where_the_choice_changes_the_answer: {
        any_policy: 2,
        by_policy: { "0d": 0, "1d": 0, "3d": 1, "7d": 1, "14d": 1, "30d": 1, "60d": 1, never: 2, critical_or_kev: 1 }
      }
    },
    ledger: [
      {
        cve_id: "CVE-2099-0001",
        published: "2024-11-28",
        severity: "high",
        exclusion: null,
        fixes: [
          { branch: "4.2", fixed_version: "4.2.9", release_date: "2024-11-27" },
          { branch: "4.4", fixed_version: "4.4.2", release_date: "2024-11-27" }
        ],
        outcomes: {
          "0d": fixFirst,
          "1d": fixFirst,
          "3d": cleared(2, "4.4.2", "2024-11-30"),
          "7d": cleared(6, "4.4.2", "2024-12-04"),
          "14d": cleared(13, "4.4.2", "2024-12-11"),
          "30d": cleared(29, "4.4.2", "2024-12-27"),
          "60d": cleared(59, "4.4.2", "2025-01-26"),
          never: open(725),
          critical_or_kev: cleared(97, "4.4.4", "2025-03-05")
        }
      },
      {
        cve_id: "CVE-2099-0002",
        published: "2025-11-06",
        severity: "medium",
        exclusion: null,
        fixes: [{ branch: "4.6", fixed_version: "4.6.1", release_date: "2025-11-05" }],
        outcomes: {
          "0d": outside,
          "1d": outside,
          "3d": outside,
          "7d": outside,
          "14d": outside,
          "30d": outside,
          "60d": outside,
          never: outside,
          critical_or_kev: outside
        }
      },
      {
        cve_id: "CVE-2099-0003",
        published: "2025-01-15",
        severity: null,
        exclusion: null,
        fixes: [{ branch: "4.4", fixed_version: "4.4.3", release_date: "2025-01-08" }],
        outcomes: {
          "0d": fixFirst,
          "1d": fixFirst,
          "3d": fixFirst,
          "7d": fixFirst,
          "14d": cleared(7, "4.4.3", "2025-01-22"),
          "30d": cleared(23, "4.4.3", "2025-02-07"),
          "60d": cleared(53, "4.4.3", "2025-03-09"),
          never: open(677),
          critical_or_kev: cleared(49, "4.4.4", "2025-03-05")
        }
      },
      {
        cve_id: "CVE-2099-0004",
        published: "2025-03-04",
        severity: "critical",
        exclusion: null,
        fixes: [{ branch: "4.4", fixed_version: "4.4.4", release_date: "2025-03-05" }],
        outcomes: {
          "0d": cleared(1, "4.4.4", "2025-03-05"),
          "1d": cleared(2, "4.4.4", "2025-03-06"),
          "3d": cleared(4, "4.4.4", "2025-03-08"),
          "7d": cleared(8, "4.4.4", "2025-03-12"),
          "14d": cleared(15, "4.4.4", "2025-03-19"),
          "30d": cleared(31, "4.4.4", "2025-04-04"),
          "60d": cleared(61, "4.4.4", "2025-05-04"),
          never: open(629),
          critical_or_kev: cleared(1, "4.4.4", "2025-03-05")
        }
      },
      { cve_id: "CVE-2099-0005", published: "2025-06-01", severity: null, exclusion: "no_configuration_for_pair", fixes: [] }
    ]
  });
}

/** Example Browser, one release line and a device that waits for each major's promotion day.
 *  Releases on its timeline: 131.0.5 on 2024-12-10 and 132.0.9 on 2025-02-04, each installed D days
 *  after that date: 0d 2024-12-10, 2025-02-04; 1d 2024-12-11, 2025-02-05; 3d 2024-12-13, 2025-02-07;
 *  7d 2024-12-17, 2025-02-11; 14d 2024-12-24, 2025-02-18; 30d 2025-01-09, 2025-03-06; 60d 2025-02-08,
 *  2025-04-05.
 *    CVE-1001 (published 2024-12-10, the day its fix 131.0.5 is dated): 0d fix first; every other day
 *      stop is exposed for exactly its D days, the days it waits; never 714, open.
 *    CVE-1002 (published 2025-02-03, the day before its fix 132.0.9): D + 1 days under each day stop,
 *      1 at 0d to 61 at 60d; never 658, open.
 *  Never seen along the slider: 1, then 0 from a day on; exposure days 1, 3, 7, 15, 29, 61, 121, 1372. */
export function singleLineReplay(): Record<string, unknown> {
  // Cloned whole: the shared pieces above are reused by both files, and a test edits its copy freely.
  return structuredClone({
    kind: "patch_policy_replay",
    schema: 3,
    run_id: "fixture-single-line",
    product: { key: "example:browser", cpe_pairs: ["example:browser"], bundle_ids: ["com.example.Browser"], device_bundle_id: "com.example.Browser" },
    window: { since: "2024-11-23", until: "2026-11-23" },
    timeline: {
      source: "example_versions",
      name: "Example Browser's version history (stable channel)",
      url: "https://example.com/browser/versions",
      fetched_at: "2026-11-24T09:20:05Z",
      sha256: "2222222222222222222222222222222222222222222222222222222222222222",
      clock: "The first UTC day the build was served on the stable channel."
    },
    definitions: {
      install,
      early_stable: "A build served before its major's promotion day is installed no earlier than that day.",
      critical_or_kev: superseded
    },
    cve_clock: "published",
    clocks,
    evidence: { branch_components: 0, parser_version: "v1", version_compare: "v0", observer: "macos" },
    counts: { cves_considered: 6, cves_outside_window: 3, cves_without_published: 0, cves_in_window: 3, cves_replayed: 2, cves_excluded: 1 },
    exclusions: {
      by_reason: reasons({ excluded_platform: 1 }),
      cves: [{ cve_id: "CVE-2099-1003", reason: "excluded_platform", published: "2025-04-02", detail: null }]
    },
    releases: [
      { version: "131.0.5", branch: "", release_date: "2024-12-10" },
      { version: "132.0.9", branch: "", release_date: "2025-02-04" }
    ],
    policies: {
      "0d": policy(0, 1, 0, 1, 1, 0, "131.0.1", installs([["2024-12-10", "131.0.5"], ["2025-02-04", "132.0.9"]])),
      "1d": policy(1, 0, 0, 2, 1 + 2, 0, "131.0.1", installs([["2024-12-11", "131.0.5"], ["2025-02-05", "132.0.9"]])),
      "3d": policy(3, 0, 0, 2, 3 + 4, 0, "131.0.1", installs([["2024-12-13", "131.0.5"], ["2025-02-07", "132.0.9"]])),
      "7d": policy(7, 0, 0, 2, 7 + 8, 0, "131.0.1", installs([["2024-12-17", "131.0.5"], ["2025-02-11", "132.0.9"]])),
      "14d": policy(14, 0, 0, 2, 14 + 15, 0, "131.0.1", installs([["2024-12-24", "131.0.5"], ["2025-02-18", "132.0.9"]])),
      "30d": policy(30, 0, 0, 2, 30 + 31, 0, "131.0.1", installs([["2025-01-09", "131.0.5"], ["2025-03-06", "132.0.9"]])),
      "60d": policy(60, 0, 0, 2, 60 + 61, 0, "131.0.1", installs([["2025-02-08", "131.0.5"], ["2025-04-05", "132.0.9"]])),
      never: policy(null, 0, 0, 2, 714 + 658, 2, "131.0.1", []),
      critical_or_kev: policy(undefined, 0, 0, 2, 9, 0, "131.0.1", installs([["2025-02-04", "132.0.9"]]))
    },
    branch_choice: {
      default_path: "hold",
      alternative_path: "latest",
      held_at_branch: null,
      cves_where_the_choice_changes_the_answer: {
        any_policy: 0,
        by_policy: { "0d": 0, "1d": 0, "3d": 0, "7d": 0, "14d": 0, "30d": 0, "60d": 0, never: 0, critical_or_kev: 0 }
      }
    },
    early_stable_choice: { device: "skip", alternative: "take", majors_with_a_promotion_date: 2, promotion_table_behind_timeline: false },
    ledger: [
      {
        cve_id: "CVE-2099-1001",
        published: "2024-12-10",
        severity: "high",
        exclusion: null,
        fixes: [{ branch: "", fixed_version: "131.0.5", release_date: "2024-12-10" }],
        outcomes: {
          "0d": fixFirst,
          "1d": cleared(1, "131.0.5", "2024-12-11"),
          "3d": cleared(3, "131.0.5", "2024-12-13"),
          "7d": cleared(7, "131.0.5", "2024-12-17"),
          "14d": cleared(14, "131.0.5", "2024-12-24"),
          "30d": cleared(30, "131.0.5", "2025-01-09"),
          "60d": cleared(60, "131.0.5", "2025-02-08"),
          never: open(714),
          critical_or_kev: cleared(7, "132.0.9", "2025-02-04")
        }
      },
      {
        cve_id: "CVE-2099-1002",
        published: "2025-02-03",
        severity: "critical",
        exclusion: null,
        fixes: [{ branch: "", fixed_version: "132.0.9", release_date: "2025-02-04" }],
        outcomes: {
          "0d": cleared(1, "132.0.9", "2025-02-04"),
          "1d": cleared(2, "132.0.9", "2025-02-05"),
          "3d": cleared(4, "132.0.9", "2025-02-07"),
          "7d": cleared(8, "132.0.9", "2025-02-11"),
          "14d": cleared(15, "132.0.9", "2025-02-18"),
          "30d": cleared(31, "132.0.9", "2025-03-06"),
          "60d": cleared(61, "132.0.9", "2025-04-05"),
          never: open(658),
          critical_or_kev: cleared(2, "132.0.9", "2025-02-04")
        }
      },
      { cve_id: "CVE-2099-1003", published: "2025-04-02", severity: "low", exclusion: "excluded_platform", fixes: [] }
    ]
  });
}
