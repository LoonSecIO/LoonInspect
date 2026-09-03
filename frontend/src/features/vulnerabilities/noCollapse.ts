/**
 * The compile-time guard that "0 findings" and "not assessed" can never share a rendering
 * (#251, `docs/vulnerabilities.md` §4a).
 *
 * There is no frontend test lane in this repo (#138), so the assertion is made in the one
 * checker CI already runs: `tsc -b --noEmit`. Every line below is an `@ts-expect-error`,
 * which is an inverted assertion — TypeScript fails the build when the error it names
 * **stops** happening. So if anyone ever widens `AppVulnerability` such that an app nobody
 * assessed carries counts, or drops the discriminant, this file goes red on the exact line
 * that describes what was lost.
 *
 * Nothing calls this. It is a proof, not a helper, and it is exported so lint does not
 * read it as dead code — deleting it would delete the guarantee, which is the one thing
 * this file is here to make expensive.
 */

import { assertExhaustive, type AppVulnerability } from "@/features/vulnerabilities/types";

/**
 * The renderer's shape, in miniature: the same exhaustive switch every surface uses, with
 * the read that must not compile attempted in each branch that has no answer to give.
 */
export function theThreeStatesCannotCollapse(vuln: AppVulnerability): number {
  switch (vuln.assessment) {
    case "off":
      // @ts-expect-error `off` means nobody looked. It carries no counts at all, so no
      // component can render it as zero findings — not by a typo, not by `?? 0`, not by
      // copying the line below. This is #251's "the trap", refused by the compiler.
      return vuln.counts.total;
    case "unknown_app":
      // @ts-expect-error An app outside the corpus is dated and uncounted. Zero here would
      // hand a reader a clean bill for an app the corpus has never heard of.
      return vuln.counts.total;
    case "covered":
      // The only branch where a number exists — and `0` here is a real clean bill,
      // because `covered` says we looked.
      return vuln.counts.total;
    default:
      // A fourth state added to the union lands here and fails to compile, rather than
      // falling through to whichever branch was last.
      return assertExhaustive(vuln);
  }
}

/**
 * The other half: the date. `corpusAsOf` rides `covered` and `unknown_app` and nothing
 * else, so a surface cannot stamp a date onto an app that was never assessed.
 */
export function offIsNeverDated(vuln: Extract<AppVulnerability, { assessment: "off" }>): string {
  // @ts-expect-error There is no corpus, so there is no corpus date. A surface says so in
  // words and dates it with nothing, rather than borrowing today's.
  return vuln.corpusAsOf;
}
