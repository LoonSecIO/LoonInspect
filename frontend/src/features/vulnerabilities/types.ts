/**
 * `vuln{}` as the API ships it — the contract of `docs/vulnerabilities.md` §4, typed so
 * the three states cannot be collapsed into one (#251).
 *
 * The union is discriminated on `assessment`, and that is the whole design. `off` has no
 * counts at all, so `vuln.counts` does not typecheck until the value has been narrowed to
 * `covered`; there is no shape in which `counts.total` can be read as `0` for an app
 * nobody assessed. That is `docs/vulnerabilities.md` §4a — *zero is not a clean bill* —
 * enforced by the compiler rather than by whoever writes the next component:
 *
 * - `covered`     — we looked. `counts.total: 0` here IS a clean bill, and it is honest
 *                   precisely because `covered` says we looked.
 * - `unknown_app` — the app is outside the corpus. Dated, and never zero vulnerabilities.
 *                   snake_case on purpose (§4b): it is the ruled value, and "fixing" it to
 *                   `unknownApp` would break every saved search that names it.
 * - `off`         — nobody looked. No corpus is loaded, so there is no date to show and
 *                   the surface says so in words.
 *
 * The names are the wire's names, deliberately: a person reading a Splunk event and a
 * person reading the page get the same three words for the same three facts.
 */

/** Findings by the corpus's severity band. The four bands need not sum to `total`: a
 *  finding the corpus carries with no severity score is in `total` and in no band (§4). */
export interface VulnSeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface VulnCounts {
  /** Active findings against THIS installed build. Never the fleet, never the app across it. */
  total: number;
  /** Of those, findings on CISA's KEV list. A flag, not a band — it overlaps the four. */
  kev: number;
  severity: VulnSeverityCounts;
}

/** Days since the publication date of the oldest active finding, overall and per band.
 *  `null` is the canonical *never*; the `-1` sentinel of §4c is minted for Splunk only, so
 *  a REST client never has to know the number exists. */
export interface VulnDaysOldestPublished {
  total: number | null;
  severity: {
    critical: number | null;
    high: number | null;
    medium: number | null;
    low: number | null;
  };
}

export type VulnAssessment = "covered" | "unknown_app" | "off";

export type AppVulnerability =
  | { assessment: "off" }
  | { assessment: "unknown_app"; corpusAsOf: string }
  | {
      assessment: "covered";
      corpusAsOf: string;
      counts: VulnCounts;
      daysOldestPublished: VulnDaysOldestPublished;
      /** Capped server-side (~50, priority KEV → severity → recency). The cap is not a wire
       *  key and can move; `vulnIDsTruncated` is what makes that safe. */
      vulnIDs: string[];
      vulnIDsTruncated: boolean;
    };

/**
 * The exhaustiveness guard. Every surface that renders an assessment switches on it and
 * ends here, so adding a fourth state to the union is a compile error in every component
 * that has not been taught the new word — rather than a silent fall-through to whichever
 * branch happened to be last.
 */
export function assertExhaustive(value: never): never {
  throw new Error(`unhandled vulnerability assessment: ${JSON.stringify(value)}`);
}

/**
 * `corpusAsOf` is a plain date ("2026-09-01"), not an instant. `new Date("2026-09-01")`
 * parses as UTC midnight and renders as the previous day everywhere west of Greenwich, so
 * the parts are read out and rebuilt in local time. A stamp that decays visibly must at
 * least be the right day.
 */
export function formatCorpusDate(value: string): string {
  const [year, month, day] = value.split("-").map(Number);
  if (!year || !month || !day) return value;
  return new Date(year, month - 1, day).toLocaleDateString();
}
