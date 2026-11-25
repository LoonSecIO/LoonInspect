import { describe, expect, it } from "vitest";
import type { MigrationItem, MigrationPortfolio, MigrationScope } from "@/features/fleetCatalog/migrationTypes";
import { fleetPlanningEnglish, fleetPlanningGerman, type FleetPlanningCopy } from "@/features/fleetCatalog/planningCopy";
import { portfolioEmpty } from "@/features/fleetCatalog/portfolioView";
import { de } from "@/i18n/de";
import { en } from "@/i18n/en";

const dictionaries = Object.values({ en, de });
const sentences = (copy: FleetPlanningCopy) => [copy.loadFailed, copy.partialCatalog, copy.notRead, copy.noJamf, copy.outsideNote,
  ...Object.values(copy.empty), ...Object.values(copy.reasons)];

describe("the migration list's words", () => {
  it("are each dictionary's fleetPlanning", () => {
    expect(en.fleetPlanning).toBe(fleetPlanningEnglish);
    expect(de.fleetPlanning).toBe(fleetPlanningGerman);
  });

  it("name each next check as main names it, so a rename on main fails here, not on an operator's screen", () => {
    for (const t of dictionaries) {
      const copy = t.fleetPlanning;
      expect(copy.noJamf).toContain(`${t.jamfPatch.eyebrow} › ${t.jamfPatch.tabLabel}`);
      expect(copy.noJamf).toContain(t.jamfPatch.syncNow);
      expect(copy.empty.noApps).toContain(t.applications.tabInstalled);
      for (const sentence of [copy.partialCatalog, copy.notRead]) expect(sentence).toContain(t.fleetCatalog.title);
      // And the list's own labels, where a sentence quotes one.
      expect(copy.empty.noMatch).toContain(copy.filters.all);
      expect(copy.noJamf.toLowerCase()).toContain(copy.filters.outside.toLowerCase());
    }
  });

  it("judge builds in the words of main's Jamf Patch legend", () => {
    for (const t of dictionaries) {
      const { legendOut, legendWithin, legendNotJudged } = t.jamfPatch.rules;
      const { policy, filters } = t.fleetPlanning;
      expect([policy.overdue, filters.overdue, policy.within, policy.unassessed]).toEqual([legendOut, legendOut, legendWithin, legendNotJudged]);
    }
  });

  it("group every count the reader's way, with the singular at 1", () => {
    const one = (copy: FleetPlanningCopy) =>
      [copy.range(1, 1, 1), copy.builds(1), copy.kev(1), copy.affected(1), copy.unassessedBuilds(1), copy.addressed(1), copy.gapAge(1)];
    expect(one(fleetPlanningEnglish)).toEqual(["1–1 of 1 app", "1 build", "KEV on 1 installed build", "1 installed build with findings",
      "1 installed build not assessed", "1 finding addressed at target", "Newer Jamf release available for 1 day"]);
    expect(one(fleetPlanningGerman)).toEqual(["1–1 von 1 App", "1 Build", "KEV in 1 installierten Build", "1 installierter Build mit Funden",
      "1 installierter Build nicht bewertet", "1 Fund in der Zielversion behoben", "Neuere Jamf-Version seit 1 Tag verfügbar"]);
    expect([fleetPlanningEnglish.builds(1234), fleetPlanningGerman.builds(1234)]).toEqual(["1,234 builds", "1.234 Builds"]);
    expect([fleetPlanningEnglish.range(1, 50, 1234), fleetPlanningGerman.range(1, 50, 1234)]).toEqual(["1–50 of 1,234 apps", "1–50 von 1.234 Apps"]);
  });

  it("point outsideNote at no app page, and name neither the list nor a segment in any sentence", () => {
    // The list's ruled name (#893), #857's, and the segment beside it, in both languages.
    const names = ["Migration review", "Migrationsprüfung", "Patch planning", "Patchplanung", "Fleet titles", "Fleet-Titel"];
    for (const copy of [fleetPlanningEnglish, fleetPlanningGerman]) {
      expect(copy.outsideNote).not.toMatch(/open|öffne|page|seite|detail/i);
      for (const sentence of sentences(copy)) for (const name of names) expect(sentence.toLowerCase()).not.toContain(name.toLowerCase());
    }
  });
});

describe("portfolioEmpty", () => {
  const app: MigrationItem = { appHash: "alpha", name: "Alpha", bundleId: "com.example.alpha", macs: 1, versionCount: 1, match: "exact",
    hasJamfMatch: false, jamfEvaluated: true, fleetCandidates: [] };
  const report = (scope: Partial<MigrationScope>, items: MigrationItem[] = []): MigrationPortfolio => ({ enabled: true,
    asOf: "2026-11-25T00:00:00Z", fleetCatalogReady: true, fleetCatalogReadiness: "complete", jamfCatalogReady: true,
    scope: { eligibleMacs: 3, selectedMacs: 1, unknownContactMacs: 0, unknownInventoryMacs: 0, ...scope },
    installedEvidence: {}, appAssessments: {}, fleetDeviceCounts: {}, items });

  it("names the first cause an operator should check, and nothing while a row shows", () => {
    // Each report below also meets every later cause, so the earlier one must win.
    expect(portfolioEmpty(report({ eligibleMacs: 0, selectedMacs: 0 }), [])).toBe("noSweep");
    expect(portfolioEmpty(report({ selectedMacs: 0 }), [])).toBe("noMacs");
    expect(portfolioEmpty(report({}), [])).toBe("noApps");
    expect(portfolioEmpty(report({}, [app]), [])).toBe("noMatch");
    expect(portfolioEmpty(report({}, [app]), [app])).toBeNull();
  });
});
