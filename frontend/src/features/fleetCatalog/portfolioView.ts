import type { FleetAssessment, InstalledEvidence, MigrationItem, MigrationPortfolio } from "./migrationTypes";

// What the migration list shows, decided without rendering anything (#902), so the node test lane holds
// it, as `catalogView.ts` does for Fleet titles. It returns keys, never words: the page words them.

export const reviewFilters = ["all", "candidates", "overdue", "exposure", "channels", "outside", "recurring", "oneTime", "unknown"] as const;
export type ReviewFilter = (typeof reviewFilters)[number];
export const portfolioSorts = ["priority", "reach", "age", "name"] as const;
export type PortfolioSort = (typeof portfolioSorts)[number];

/** The URL's `filter` and `sort`. A value this build does not know reads as the default. */
export const readFilter = (value: string | null): ReviewFilter => reviewFilters.find(filter => filter === value) ?? "all";
export const readSort = (value: string | null): PortfolioSort => portfolioSorts.find(sort => sort === value) ?? "priority";

/** In neither Fleet's catalog nor Jamf's patch catalog. Never claimed from a partly read Fleet catalog:
 *  the app's title could be in the part that was not read. */
export function outsideCatalogs(item: MigrationItem, report: MigrationPortfolio): boolean {
  return report.fleetCatalogReady && report.jamfCatalogReady && item.match === "none" && item.jamfEvaluated && !item.hasJamfMatch;
}

export const needsReview = (a?: FleetAssessment): boolean => a?.priority === "review_now" || a?.priority === "plan_update";

// Keep unknown evidence neutral: a null count weighs as 0. Reach is bounded so a widely installed app
// alone cannot outrank an observed policy breach or a known exploited vulnerability.
function reviewWeight(item: MigrationItem, a?: FleetAssessment, evidence?: InstalledEvidence): number {
  const prevalence = Math.min(10, Math.log2(item.macs + 1));
  const severity = (evidence?.highOrCriticalBuilds ?? 0) > 0 ? 8 : 0;
  const exploited = (evidence?.kevBuilds ?? 0) > 0 || (a?.kevBuilds ?? 0) > 0 ? 40 : 0;
  if (!a) return prevalence + severity + exploited;
  const gapAge = Math.min(6, (a.oldestGapDays ?? 0) / 14);
  return prevalence + severity + exploited + gapAge
    + 24 * Number(a.outOfPolicyBuilds > 0) + 15 * Number((a.addresses ?? 0) > 0)
    + 6 * Number(a.behindBuilds > 0) + 3 * Number(a.management === "recurring");
}

function matchesFilter(item: MigrationItem, report: MigrationPortfolio, filter: ReviewFilter): boolean {
  const a = report.appAssessments[item.appHash];
  const evidence = report.installedEvidence[item.appHash];
  switch (filter) {
    case "candidates": return needsReview(a);
    case "overdue": return (a?.outOfPolicyBuilds ?? 0) > 0;
    case "exposure": return (evidence?.affectedBuilds ?? 0) > 0 || (a?.addresses ?? 0) > 0;
    case "recurring": return a?.management === "recurring";
    case "oneTime": return a?.management === "one_time";
    case "channels": return item.match === "ambiguous";
    case "outside": return outsideCatalogs(item, report);
    // An app with no evidence entry is unknown too.
    case "unknown": return item.match === "unknown" || !item.jamfEvaluated || evidence?.assessment !== "covered"
      || (item.match === "exact" && (!a || a.policyUnassessedBuilds > 0 || a.unknownBuilds > 0 || a.netOnlyBuilds > 0));
    default: return true;
  }
}

/** The apps the search (name, bundle ID or Fleet title name) and the filter keep, in the sort's order.
 *  `priority` and `age` break ties by Macs, as `reach` sorts; every sort ends on the name, then the app hash. */
export function portfolioRows(report: MigrationPortfolio, search: string, filter: ReviewFilter, sort: PortfolioSort): MigrationItem[] {
  const needle = search.trim().toLowerCase();
  const found = (item: MigrationItem) =>
    [item.name, item.bundleId, ...item.fleetCandidates.map(title => title.name)].some(value => value.toLowerCase().includes(needle));
  const weight = (item: MigrationItem) => reviewWeight(item, report.appAssessments[item.appHash], report.installedEvidence[item.appHash]);
  const age = (item: MigrationItem) => report.appAssessments[item.appHash]?.oldestGapDays ?? -1;
  return report.items.filter(item => found(item) && matchesFilter(item, report, filter)).sort((left, right) =>
    (sort === "age" ? age(right) - age(left) : 0)
    || (sort === "priority" ? weight(right) - weight(left) : 0)
    || (sort === "name" ? 0 : right.macs - left.macs)
    || left.name.localeCompare(right.name) || left.appHash.localeCompare(right.appHash));
}

/** The three quick filters' counts, over every app in the scope whatever the search hides. `outside` is null,
 *  never 0, until Fleet's catalog is read whole and Jamf's patch catalog is synced: the page says Unknown. */
export function quickCounts(report: MigrationPortfolio): { candidates: number; overdue: number; outside: number | null } {
  const count = (filter: ReviewFilter) => report.items.filter(item => matchesFilter(item, report, filter)).length;
  const known = report.fleetCatalogReady && report.jamfCatalogReady;
  return { candidates: count("candidates"), overdue: count("overdue"), outside: known ? count("outside") : null };
}

export type CoverageKey = "outside" | "fleet" | "channels" | "jamf" | "noFleet" | "unavailable";

/** `outside` alone; else `fleet` or `channels`, and `jamf`; else `noFleet` or `unavailable`. */
export function coverage(item: MigrationItem, report: MigrationPortfolio): CoverageKey[] {
  if (outsideCatalogs(item, report)) return ["outside"];
  const keys: CoverageKey[] = item.match === "exact" ? ["fleet"] : item.match === "ambiguous" ? ["channels"] : [];
  if (item.hasJamfMatch) keys.push("jamf");
  return keys.length ? keys : [item.match === "none" ? "noFleet" : "unavailable"];
}

export type PolicySummary = "overdue" | "partial" | "within" | "exempt" | "unassessed";

/** An app's builds against the confirmed patch rule: one build out of policy makes it `overdue`. */
export function policySummary(a?: FleetAssessment): PolicySummary {
  if (!a) return "unassessed";
  if (a.outOfPolicyBuilds) return "overdue";
  if (a.policyUnassessedBuilds) return a.withinPolicyBuilds || a.policyExemptBuilds ? "partial" : "unassessed";
  if (a.withinPolicyBuilds) return "within";
  if (a.policyExemptBuilds) return "exempt";
  return "unassessed";
}

export type PortfolioEmpty = "noSweep" | "noMacs" | "noApps" | "noMatch";

/** Which kind of empty the list is (docs/diagnosability.md rule 1), checked in the order an operator should: no
 *  current Jamf Mac on record, none the device filter keeps, no installed app on those it keeps, or the search and
 *  the Show choice hide every app. Null while any row shows. Ask it only of an enabled report: with the flag off the
 *  report counts nothing, and the page says the flag is off instead. */
export function portfolioEmpty(report: MigrationPortfolio, rows: MigrationItem[]): PortfolioEmpty | null {
  if (rows.length) return null;
  if (!report.scope.eligibleMacs) return "noSweep";
  if (!report.scope.selectedMacs) return "noMacs";
  return report.items.length ? "noMatch" : "noApps";
}
