/**
 * The built-in patch-policy definitions (#954, ruled 2026-11-28), as the page reads them. A definition
 * is data the instance's walk runs in place of a slider stop: `{id, name, otherwise, when[]}`, where
 * `otherwise` is a day count or `never` and each trigger names a closed kind (`kev_listed`,
 * `critical`, `critical_or_high`) and the days it waits. The walk computes every number; this module
 * holds only the ids this build knows, so an address can name one (`?policy=kev-only`) before a walk
 * has loaded, and the reader of the reference replays can tell a row keyed by one.
 *
 * Built in only (ruled 2026-11-28): none is an organization's own rule or a file an operator
 * supplies, and none is named for a framework. Pure, like `replay.ts`: no fetch, no router, no locale.
 */

/** The ids of the built-in definitions, in the walk's order (`POLICIES` after the stops). */
export const POLICY_DEFINITION_IDS = ["kev-only", "critical-only", "30d-or-kev"] as const;
export type DefinitionId = (typeof POLICY_DEFINITION_IDS)[number];
export const isDefinitionId = (value: string | null): value is DefinitionId => POLICY_DEFINITION_IDS.includes(value as DefinitionId);

/** The closed set of trigger kinds a definition's `when` may name. */
export type TriggerKind = "kev_listed" | "critical" | "critical_or_high";
export const TRIGGER_KINDS: readonly TriggerKind[] = ["kev_listed", "critical", "critical_or_high"];
export const SEVERITY_KINDS: readonly TriggerKind[] = ["critical", "critical_or_high"];

export interface PolicyTrigger {
  fixes: TriggerKind | string;
  within_days: number;
}

/** A definition as the walk answers it (`policy_definitions[]`). */
export interface PolicyDefinition {
  id: string;
  name: string;
  otherwise: number | "never";
  when: PolicyTrigger[];
}

/** What installed a release under a definition (`installs[].by`, `opening_by`): `otherwise`, or a
 *  trigger, with its CVE, the day its fact was knowable, and that day's basis. */
export interface InstallCause {
  rule: "otherwise" | TriggerKind | string;
  cve_id: string | null;
  on: string | null;
  /** `kev_date_added`; for a severity trigger `first_scored`, the day LoonSec's data states, or
   *  `clock_day`, the CVE's clock day standing in, with today's severity (ruled 2026-11-28). */
  basis: "kev_date_added" | "first_scored" | "clock_day" | string | null;
}

/** The day a CVE's fact was knowable for one trigger kind, and its basis (`cves[].knowable`). */
export interface KnowableFact {
  on: string;
  basis: "kev_date_added" | "first_scored" | "clock_day" | string;
}

/** A definition the walk could not run on this data (`policy_refusals`), in the instance's words. */
export interface DefinitionRefusal {
  reason: string;
  sentence: string;
}

const isObject = (value: unknown): value is Record<string, unknown> => typeof value === "object" && value !== null && !Array.isArray(value);

/** The definitions an answer carries, read tolerantly: an entry this build cannot read is skipped. */
export function definitionsOf(value: unknown): PolicyDefinition[] {
  if (!Array.isArray(value)) return [];
  return value.flatMap((entry): PolicyDefinition[] => {
    if (!isObject(entry) || typeof entry.id !== "string" || typeof entry.name !== "string") return [];
    const otherwise = entry.otherwise === "never" || typeof entry.otherwise === "number" ? entry.otherwise : null;
    if (otherwise === null || !Array.isArray(entry.when)) return [];
    const when = entry.when.flatMap((trigger): PolicyTrigger[] =>
      isObject(trigger) && typeof trigger.fixes === "string" && typeof trigger.within_days === "number" ? [{ fixes: trigger.fixes, within_days: trigger.within_days }] : []
    );
    return [{ id: entry.id, name: entry.name, otherwise, when }];
  });
}

/** Whether a definition reads a severity, so the page says which day stood in for each CVE. */
export const readsSeverity = (definition: Pick<PolicyDefinition, "when">): boolean => definition.when.some((trigger) => SEVERITY_KINDS.includes(trigger.fixes as TriggerKind));
