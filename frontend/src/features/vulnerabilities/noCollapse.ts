/**
 * The compile-time guard that "0 findings" and "not assessed" can never share a rendering
 * (#251, `docs/vulnerabilities.md` §4a).
 *
 * There is no frontend test lane in this repo (#138), so the assertion is made in the one
 * checker CI already runs: `tsc -b --noEmit`.
 *
 * **Why not `@ts-expect-error`.** The first version of this file wrote the illegal reads
 * out and suppressed them. That guard was too loose to be worth having: `@ts-expect-error`
 * is satisfied by *any* error on its line, so widening the `off` member with an
 * **optional** `counts?: VulnCounts` would have kept this file green — the read still
 * errors, now on strict-null grounds — while `vuln.counts?.total ?? 0` quietly started
 * compiling in every component. The guard would have been passing for a reason unrelated
 * to the one it claimed.
 *
 * So the assertions below are about the *shape of the type* rather than about whether some
 * expression happens to error. `"counts" extends keyof T` is true for an optional property
 * as well as a required one, which is exactly the hole the old version missed: the only way
 * to satisfy `NoKey<Off, "counts">` is for `counts` to be genuinely absent from the `off`
 * member. Nothing runs; nothing is exported for use. Deleting this file deletes the
 * guarantee, which is the one thing it exists to make expensive.
 */

import type { AppVulnerability, VulnAssessment } from "@/features/vulnerabilities/types";

/** Fails to compile unless `T` is exactly `true`. */
type Assert<T extends true> = T;

/** `true` when `K` is not a key of `T` **at all** — optional included. */
type NoKey<T, K extends PropertyKey> = K extends keyof T ? false : true;

/** `true` when `T` has `K` and `K` is required rather than optional. */
type RequiredKey<T, K extends keyof T> = object extends Pick<T, K> ? false : true;

type Off = Extract<AppVulnerability, { assessment: "off" }>;
type UnknownApp = Extract<AppVulnerability, { assessment: "unknown_app" }>;
type Covered = Extract<AppVulnerability, { assessment: "covered" }>;

// --- The trap, refused (#251) ---------------------------------------------------------
// `off` means nobody looked. There is no count on it to render as zero — not via a typo,
// not via `?? 0`, not via `?.total`, because the property does not exist to be optional.
export type OffCarriesNoCounts = Assert<NoKey<Off, "counts">>;
export type OffCarriesNoIDs = Assert<NoKey<Off, "vulnIDs">>;
// And no date: there is no corpus, so there is nothing to stamp a row with. A surface says
// so in words rather than borrowing today's.
export type OffCarriesNoDate = Assert<NoKey<Off, "corpusAsOf">>;

// An app outside the corpus is dated and uncounted. Zero here would hand a reader a clean
// bill for an app the corpus has never heard of.
export type UnknownAppCarriesNoCounts = Assert<NoKey<UnknownApp, "counts">>;
export type UnknownAppIsDated = Assert<RequiredKey<UnknownApp, "corpusAsOf">>;

// `covered` is the only member with a number, and it carries one *requiredly*: making it
// optional would put the clean-bill branch back within reach of `?? 0`.
export type CoveredCountsAreRequired = Assert<RequiredKey<Covered, "counts">>;
export type CoveredIsDated = Assert<RequiredKey<Covered, "corpusAsOf">>;

// --- The vocabulary is exactly three --------------------------------------------------
// A fourth member added to the union without a `VulnAssessment` value (or the reverse)
// fails here, and every exhaustive `switch` over the union fails at its own `default`.
export type TheStatesAreExactlyThree = Assert<
  [AppVulnerability["assessment"]] extends [VulnAssessment]
    ? [VulnAssessment] extends [AppVulnerability["assessment"]]
      ? true
      : false
    : false
>;
