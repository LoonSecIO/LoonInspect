/**
 * Hand-made schema-2 replay files for the patch-policy tests (#614), and nothing else: no module the
 * app loads imports this one, so it never reaches the build. Two shapes the page must draw:
 *
 * - `heldLineReplay`: an app with several release lines, held on `4.4` (`branch_components` 2).
 * - `singleLineReplay`: an app replayed as one line (`branch_components` 0): `held_at_branch` is
 *   `null` and every fix is on the line `""`. Its device waits for a major's promotion day (`skip`).
 *
 * Every value is invented. The CVE ids are in 2099, the timelines are on example.com and the run ids
 * say `fixture`, so nothing here can be read as a finding about a real app. The replays the page
 * ships are the generated files under `../replays/`, and `../replays/README.md` names their sources.
 * The totals close, so `readReplay` accepts both as they stand; each call returns a fresh copy.
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

const policy = (
  never_seen: number,
  never_seen_outside_affected_range: number,
  exposed: number,
  exposure_days: number,
  open_at_window_end: number,
  initial_version: string,
  installs: { date: string; version: string }[]
) => ({
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

const tabled =
  "TABLED 2026-10-02, not ruled: do not quote this row. As computed, a release is installed on the first day a CVE it fixes is KEV-listed or critical.";

/** Example App, held on 4.4. Releases on its timeline: 4.4.2 on 2024-11-27, 4.4.3 on 2025-01-08 and
 *  4.4.4 on 2025-03-05; a D-day device installs each D − 1 days later. */
export function heldLineReplay(): Record<string, unknown> {
  // Cloned whole: the shared pieces above are reused by both files, and a test edits its copy freely.
  return structuredClone({
    kind: "patch_policy_replay",
    schema: 2,
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
      install: "A policy of D days installs each release by the D-th day; the release's date on the timeline is day one.",
      never: "The device stays on the version that was current when the window opened.",
      critical_or_kev: tabled
    },
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
      "1d": policy(3, 1, 1, 1, 0, "4.4.1", installs([["2024-11-27", "4.4.2"], ["2025-01-08", "4.4.3"], ["2025-03-05", "4.4.4"]])),
      "7d": policy(2, 1, 2, 12, 0, "4.4.1", installs([["2024-12-03", "4.4.2"], ["2025-01-14", "4.4.3"], ["2025-03-11", "4.4.4"]])),
      "14d": policy(1, 1, 3, 32, 0, "4.4.1", installs([["2024-12-10", "4.4.2"], ["2025-01-21", "4.4.3"], ["2025-03-18", "4.4.4"]])),
      "30d": policy(1, 1, 3, 80, 0, "4.4.1", installs([["2024-12-26", "4.4.2"], ["2025-02-06", "4.4.3"], ["2025-04-03", "4.4.4"]])),
      "60d": policy(1, 1, 3, 170, 0, "4.4.1", installs([["2025-01-25", "4.4.2"], ["2025-03-08", "4.4.3"], ["2025-05-03", "4.4.4"]])),
      never: policy(1, 1, 3, 2031, 3, "4.4.1", []),
      critical_or_kev: policy(1, 1, 3, 147, 0, "4.4.1", installs([["2025-03-05", "4.4.4"]]))
    },
    branch_choice: {
      default_path: "hold",
      alternative_path: "latest",
      held_at_branch: "4.4",
      cves_where_the_choice_changes_the_answer: {
        any_policy: 2,
        by_policy: { "1d": 0, "7d": 1, "14d": 1, "30d": 1, "60d": 1, never: 2, critical_or_kev: 1 }
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
          "1d": fixFirst,
          "7d": cleared(5, "4.4.2", "2024-12-03"),
          "14d": cleared(12, "4.4.2", "2024-12-10"),
          "30d": cleared(28, "4.4.2", "2024-12-26"),
          "60d": cleared(58, "4.4.2", "2025-01-25"),
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
        outcomes: { "1d": outside, "7d": outside, "14d": outside, "30d": outside, "60d": outside, never: outside, critical_or_kev: outside }
      },
      {
        cve_id: "CVE-2099-0003",
        published: "2025-01-15",
        severity: null,
        exclusion: null,
        fixes: [{ branch: "4.4", fixed_version: "4.4.3", release_date: "2025-01-08" }],
        outcomes: {
          "1d": fixFirst,
          "7d": fixFirst,
          "14d": cleared(6, "4.4.3", "2025-01-21"),
          "30d": cleared(22, "4.4.3", "2025-02-06"),
          "60d": cleared(52, "4.4.3", "2025-03-08"),
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
          "1d": cleared(1, "4.4.4", "2025-03-05"),
          "7d": cleared(7, "4.4.4", "2025-03-11"),
          "14d": cleared(14, "4.4.4", "2025-03-18"),
          "30d": cleared(30, "4.4.4", "2025-04-03"),
          "60d": cleared(60, "4.4.4", "2025-05-03"),
          never: open(629),
          critical_or_kev: cleared(1, "4.4.4", "2025-03-05")
        }
      },
      { cve_id: "CVE-2099-0005", published: "2025-06-01", severity: null, exclusion: "no_configuration_for_pair", fixes: [] }
    ]
  });
}

/** Example Browser, one release line and a device that waits for each major's promotion day. */
export function singleLineReplay(): Record<string, unknown> {
  // Cloned whole: the shared pieces above are reused by both files, and a test edits its copy freely.
  return structuredClone({
    kind: "patch_policy_replay",
    schema: 2,
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
      install: "A policy of D days installs each release by the D-th day; the release's date on the timeline is day one.",
      early_stable: "A build served before its major's promotion day is installed no earlier than that day.",
      critical_or_kev: tabled
    },
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
      "1d": policy(1, 0, 1, 1, 0, "131.0.1", installs([["2024-12-10", "131.0.5"], ["2025-02-04", "132.0.9"]])),
      "7d": policy(0, 0, 2, 13, 0, "131.0.1", installs([["2024-12-16", "131.0.5"], ["2025-02-10", "132.0.9"]])),
      "14d": policy(0, 0, 2, 27, 0, "131.0.1", installs([["2024-12-23", "131.0.5"], ["2025-02-17", "132.0.9"]])),
      "30d": policy(0, 0, 2, 59, 0, "131.0.1", installs([["2025-01-08", "131.0.5"], ["2025-03-05", "132.0.9"]])),
      "60d": policy(0, 0, 2, 119, 0, "131.0.1", installs([["2025-02-07", "131.0.5"], ["2025-04-04", "132.0.9"]])),
      never: policy(0, 0, 2, 1372, 2, "131.0.1", []),
      critical_or_kev: policy(0, 0, 2, 9, 0, "131.0.1", installs([["2025-02-04", "132.0.9"]]))
    },
    branch_choice: {
      default_path: "hold",
      alternative_path: "latest",
      held_at_branch: null,
      cves_where_the_choice_changes_the_answer: {
        any_policy: 0,
        by_policy: { "1d": 0, "7d": 0, "14d": 0, "30d": 0, "60d": 0, never: 0, critical_or_kev: 0 }
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
          "1d": fixFirst,
          "7d": cleared(6, "131.0.5", "2024-12-16"),
          "14d": cleared(13, "131.0.5", "2024-12-23"),
          "30d": cleared(29, "131.0.5", "2025-01-08"),
          "60d": cleared(59, "131.0.5", "2025-02-07"),
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
          "1d": cleared(1, "132.0.9", "2025-02-04"),
          "7d": cleared(7, "132.0.9", "2025-02-10"),
          "14d": cleared(14, "132.0.9", "2025-02-17"),
          "30d": cleared(30, "132.0.9", "2025-03-05"),
          "60d": cleared(60, "132.0.9", "2025-04-04"),
          never: open(658),
          critical_or_kev: cleared(2, "132.0.9", "2025-02-04")
        }
      },
      { cve_id: "CVE-2099-1003", published: "2025-04-02", severity: "low", exclusion: "excluded_platform", fixes: [] }
    ]
  });
}
