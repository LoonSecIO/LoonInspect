import type { FleetAssessment, InstalledEvidence, MigrationItem, MigrationPortfolio } from "./migrationTypes";

export const reviewFilters = ["all", "candidates", "overdue", "exposure", "channels", "outside", "recurring", "oneTime", "unknown"] as const;

export function outsideCatalogs(item: MigrationItem, report: MigrationPortfolio) {
  return report.fleetCatalogReady && report.jamfCatalogReady && item.match === "none" && item.jamfEvaluated && !item.hasJamfMatch;
}

export function needsReview(a?: FleetAssessment) {
  return a?.priority === "review_now" || a?.priority === "plan_update";
}

// Keep unknown evidence neutral. Reach is bounded so a widely installed app alone
// cannot outrank an observed policy breach or a known exploited vulnerability.
function reviewWeight(item: MigrationItem, a?: FleetAssessment, evidence?: InstalledEvidence): number {
  const prevalence = Math.min(10, Math.log2(item.macs + 1));
  const severity = evidence?.highOrCriticalBuilds ? 8 : 0;
  const exploited = evidence?.kevBuilds || a?.kevBuilds ? 40 : 0;
  if (!a) return prevalence + severity + exploited;
  const gapAge = Math.min(6, (a.oldestGapDays ?? 0) / 14);
  return prevalence + severity + exploited + gapAge
    + 24 * Number(a.outOfPolicyBuilds > 0) + 15 * Number((a.addresses ?? 0) > 0)
    + 6 * Number(a.behindBuilds > 0) + 3 * Number(a.management === "recurring");
}

export function portfolioRows(report: MigrationPortfolio, search: string, filter: string, sort: string) {
  const needle = search.trim().toLowerCase();
  return report.items.filter(item => {
    if (needle && ![item.name, item.bundleId, ...item.fleetCandidates.map(c => c.name)].some(v => v.toLowerCase().includes(needle))) return false;
    const a = report.appAssessments[item.appHash];
    switch (filter) {
      case "candidates": return needsReview(a);
      case "overdue": return (a?.outOfPolicyBuilds ?? 0) > 0;
      case "exposure": return (report.installedEvidence[item.appHash]?.affectedBuilds ?? 0) > 0 || (a?.addresses ?? 0) > 0;
      case "recurring": return a?.management === "recurring";
      case "oneTime": return a?.management === "one_time";
      case "channels": return item.match === "ambiguous";
      case "outside": return outsideCatalogs(item, report);
      case "unknown": {
        const evidence = report.installedEvidence[item.appHash];
        return item.match === "unknown" || !item.jamfEvaluated || !evidence?.assessedBuilds || evidence.unknownBuilds > 0
          || (item.match === "exact" && (!a || a.policyUnassessedBuilds > 0 || a.unknownBuilds > 0 || a.netOnlyBuilds > 0));
      }
      default: return true;
    }
  }).sort((left, right) => {
    if (sort === "age") {
      const delta = (report.appAssessments[right.appHash]?.oldestGapDays ?? -1) - (report.appAssessments[left.appHash]?.oldestGapDays ?? -1);
      if (delta) return delta;
    }
    if (sort === "priority") {
      const delta = reviewWeight(right, report.appAssessments[right.appHash], report.installedEvidence[right.appHash])
        - reviewWeight(left, report.appAssessments[left.appHash], report.installedEvidence[left.appHash]);
      if (delta) return delta;
    }
    if (sort !== "name" && left.macs !== right.macs) return right.macs - left.macs;
    return left.name.localeCompare(right.name) || left.appHash.localeCompare(right.appHash);
  });
}

export function policySummary(a?: FleetAssessment) {
  if (!a) return "unassessed";
  if (a.outOfPolicyBuilds) return "overdue";
  if (a.policyUnassessedBuilds) return a.withinPolicyBuilds || a.policyExemptBuilds ? "partial" : "unassessed";
  if (a.withinPolicyBuilds) return "within";
  if (a.policyExemptBuilds) return "exempt";
  return "unassessed";
}
