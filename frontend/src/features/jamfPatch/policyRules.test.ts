import { describe, expect, it } from "vitest";
import { draftOf, judges, policySentence, ruleOf, sameRule } from "@/features/jamfPatch/policyRules";
import { en } from "@/i18n/en";

describe("ruleOf", () => {
  const none = { days: "", severeDays: "", releases: "" };

  it("reads whole numbers and takes an empty box as no limit", () => {
    expect(ruleOf({ ...none, days: " 14 " })).toEqual({
      rule: { maxDaysBehind: 14, maxReleasesBehind: null, maxDaysBehindSevere: null }
    });
    expect(ruleOf({ ...none, releases: "0" })).toEqual({
      rule: { maxDaysBehind: null, maxReleasesBehind: 0, maxDaysBehindSevere: null }
    });
    expect(ruleOf(none)).toEqual({ rule: { maxDaysBehind: null, maxReleasesBehind: null, maxDaysBehindSevere: null } });
  });

  it("names the field it cannot read rather than guessing a number", () => {
    for (const days of ["two weeks", "-1", "1.5", "14d", "3651"]) {
      expect(ruleOf({ ...none, days })).toEqual({ problem: "days" });
    }
    expect(ruleOf({ ...none, days: "14", releases: "1001" })).toEqual({ problem: "releases" });
    expect(ruleOf({ ...none, severeDays: "soon" })).toEqual({ problem: "severeDays" });
  });

  it("reads highs and criticals within two weeks, else sixty days", () => {
    expect(ruleOf({ days: "60", severeDays: "14", releases: "" })).toEqual({
      rule: { maxDaysBehind: 60, maxReleasesBehind: null, maxDaysBehindSevere: 14 }
    });
  });

  it("refuses a severe limit longer than the ordinary one, and takes one on its own", () => {
    expect(ruleOf({ days: "14", severeDays: "60", releases: "" })).toEqual({ problem: "severeLooser" });
    expect(ruleOf({ ...none, severeDays: "7" })).toEqual({
      rule: { maxDaysBehind: null, maxReleasesBehind: null, maxDaysBehindSevere: 7 }
    });
  });
});

describe("draftOf", () => {
  it("round-trips a rule, and opens empty where there is none", () => {
    const rule = { maxDaysBehind: 30, maxReleasesBehind: null, maxDaysBehindSevere: 7 };
    expect(ruleOf(draftOf(rule))).toEqual({ rule });
    expect(draftOf(null)).toEqual({ days: "", severeDays: "", releases: "" });
  });
});

describe("judges", () => {
  const none = { maxDaysBehind: null, maxReleasesBehind: null, maxDaysBehindSevere: null };

  it("is false for no rule and for a rule with no limit, and true for any limit, zero included", () => {
    expect(judges(null)).toBe(false);
    expect(judges(none)).toBe(false);
    expect(judges({ ...none, maxDaysBehind: 0 })).toBe(true);
    expect(judges({ ...none, maxDaysBehindSevere: 14 })).toBe(true);
  });
});

describe("sameRule", () => {
  const fourteen = { maxDaysBehind: 14, maxReleasesBehind: null, maxDaysBehindSevere: null };

  it("is true only limit for limit, which is what lets a rule keep its basis", () => {
    expect(sameRule(fourteen, { ...fourteen })).toBe(true);
    expect(sameRule(fourteen, { ...fourteen, maxDaysBehind: 30 })).toBe(false);
    expect(sameRule(fourteen, { ...fourteen, maxReleasesBehind: 1 })).toBe(false);
    expect(sameRule(fourteen, { ...fourteen, maxDaysBehindSevere: 7 })).toBe(false);
  });
});

describe("policySentence", () => {
  const limits = { maxReleasesBehind: 1, maxDaysBehindSevere: null };
  const verdict = { reason: null, since: null, daysBehind: null, releasesBehind: null, limitDays: null, severe: null };

  it("says since when, how long and against which limit for the days rule", () => {
    const sentence = policySentence(
      { ...verdict, state: "out", reason: "days", since: "2026-08-15T12:00:00Z", daysBehind: 63, releasesBehind: 4, limitDays: 14 },
      limits,
      en
    );
    expect(sentence).toContain("63 days (limit 14)");
    expect(sentence).toContain(new Date("2026-08-15T12:00:00Z").toLocaleDateString());
  });

  it("names the severe limit when that is the one that judged the build", () => {
    const sentence = policySentence(
      { ...verdict, state: "out", reason: "days", since: "2026-08-15T12:00:00Z", daysBehind: 30, releasesBehind: 1, limitDays: 14, severe: true },
      { maxReleasesBehind: null, maxDaysBehindSevere: 14 },
      en
    );
    expect(sentence).toContain("(limit 14, this build carries a critical or high finding)");
  });

  it("says when a behind build was judged by the ordinary limit because nobody assessed it", () => {
    const split = { maxReleasesBehind: null, maxDaysBehindSevere: 14 };
    const behind = { ...verdict, state: "within" as const, daysBehind: 30, releasesBehind: 1, limitDays: 60 };
    expect(policySentence(behind, split, en)).toContain("has not assessed this build");
    // Not said of a build that was assessed, of one on the latest, or under a rule with no severe limit.
    expect(policySentence({ ...behind, severe: false }, split, en)).toBe("Within policy");
    expect(policySentence({ ...behind, releasesBehind: 0 }, split, en)).toBe("Within policy");
    expect(policySentence(behind, limits, en)).toBe("Within policy");
  });

  it("counts releases for the releases rule, and never prints a date it does not have", () => {
    const sentence = policySentence({ ...verdict, state: "out", reason: "releases", releasesBehind: 3 }, limits, en);
    expect(sentence).toBe("Out of policy: 3 newer releases listed (limit 1)");
  });

  it("keeps within, not judged and a bare out apart", () => {
    expect(policySentence({ ...verdict, state: "within" }, limits, en)).toBe("Within policy");
    expect(policySentence({ ...verdict, state: "not_judged" }, limits, en)).toContain("Not judged");
    expect(policySentence({ ...verdict, state: "out" }, limits, en)).toBe("Out of policy");
  });
});
