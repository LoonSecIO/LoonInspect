/**
 * The patching rule's page-side half — pure, so what the editor accepts and what the page
 * says a rule means are pinned in the node lane (`policyRules.test.ts`).
 *
 * The verdicts themselves are not computed here: the API judges every version
 * (`app.mdm.patch.policy`) and the page renders its answer, so the page and a second client
 * of the same API cannot disagree about one build.
 */
import type { PatchRule, PolicyVersion } from "@/features/jamfPatch/types";
import type { Translations } from "@/i18n/en";

/** The API's own bounds; past them a number is a typo, and the route refuses it too. */
export const MAX_DAYS = 3650;
export const MAX_RELEASES = 1000;

/** The editor's fields, as typed: text, so an empty box can mean "no limit". */
export interface RuleDraft {
  days: string;
  /** The days limit for builds with critical or high findings. */
  severeDays: string;
  releases: string;
}

export const EMPTY_DRAFT: RuleDraft = { days: "", severeDays: "", releases: "" };

export function draftOf(rule: PatchRule | null): RuleDraft {
  const text = (value: number | null | undefined) => (value == null ? "" : String(value));
  return { days: text(rule?.maxDaysBehind), severeDays: text(rule?.maxDaysBehindSevere), releases: text(rule?.maxReleasesBehind) };
}

/** A box that cannot be read, or `severeLooser`: both day limits read, and the one for
 *  severe builds is the longer — it replaces the ordinary limit, so it cannot be. */
export type DraftProblem = "days" | "severeDays" | "releases" | "severeLooser";

/** A typed limit as a number, `null` for an empty box, or `undefined` for text that is not
 *  a whole number inside the bounds. */
function limit(text: string, ceiling: number): number | null | undefined {
  const trimmed = text.trim();
  if (trimmed === "") return null;
  if (!/^\d+$/.test(trimmed)) return undefined;
  const value = Number(trimmed);
  return value <= ceiling ? value : undefined;
}

/** The rule a draft says, or which field cannot be read. An empty draft is a rule with no
 *  limits — how a rule is cleared — and is not a problem here; the caller decides whether
 *  clearing is allowed where it stands. */
export function ruleOf(draft: RuleDraft): { rule: PatchRule } | { problem: DraftProblem } {
  const days = limit(draft.days, MAX_DAYS);
  if (days === undefined) return { problem: "days" };
  const severeDays = limit(draft.severeDays, MAX_DAYS);
  if (severeDays === undefined) return { problem: "severeDays" };
  const releases = limit(draft.releases, MAX_RELEASES);
  if (releases === undefined) return { problem: "releases" };
  if (days !== null && severeDays !== null && severeDays > days) return { problem: "severeLooser" };
  return { rule: { maxDaysBehind: days, maxReleasesBehind: releases, maxDaysBehindSevere: severeDays } };
}

/** Whether a rule can put a build out of policy at all. */
export function judges(rule: PatchRule | null): boolean {
  return (
    rule !== null && (rule.maxDaysBehind !== null || rule.maxReleasesBehind !== null || rule.maxDaysBehindSevere !== null)
  );
}

/** One version's verdict as the sentence the table and the tooltip both print. The days
 *  limit named is the one that judged this version (`limitDays`), and a version judged by
 *  the ordinary limit because the corpus has not assessed it says so. */
export function policySentence(
  verdict: PolicyVersion,
  limits: { maxReleasesBehind: number | null; maxDaysBehindSevere: number | null },
  t: Translations
): string {
  const copy = t.jamfPatch.rules;
  if (verdict.state === "not_judged") return copy.verdictNotJudged;
  // Said only where it changed which limit applied: a build that is behind, under a rule
  // with a severe limit, that the corpus has not assessed.
  const unassessed =
    limits.maxDaysBehindSevere !== null && verdict.severe === null && (verdict.releasesBehind ?? 0) > 0
      ? ` ${copy.verdictSeverityUnknown}`
      : "";
  if (verdict.state === "within") return copy.verdictWithin + unassessed;
  if (verdict.reason === "days" && verdict.since !== null && verdict.daysBehind !== null && verdict.limitDays !== null) {
    const since = new Date(verdict.since).toLocaleDateString();
    return copy.verdictOutDays(since, verdict.daysBehind, verdict.limitDays, verdict.severe === true) + unassessed;
  }
  if (verdict.reason === "releases" && verdict.releasesBehind !== null && limits.maxReleasesBehind !== null) {
    return copy.verdictOutReleases(verdict.releasesBehind, limits.maxReleasesBehind) + unassessed;
  }
  return copy.verdictOut;
}
