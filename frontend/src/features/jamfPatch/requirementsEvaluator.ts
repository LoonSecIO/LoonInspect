import type { JamfPatchRequirementGroup, JamfPatchRequirementTest } from "@/features/jamfPatch/types";

export interface TestFacts {
  appName: string;
  bundleId: string;
  shortVersion: string;
  bundleVersion: string;
  extensionAttributeName: string;
  extensionAttributeValue: string;
}

export type TestOutcome = "pass" | "fail" | "not_applicable";
export type GroupVerdict = "matched" | "not_matched" | "inconclusive";
export type OverallVerdict = "matched" | "not_matched" | "inconclusive";

export interface TestResult {
  test: JamfPatchRequirementTest;
  outcome: TestOutcome;
}

export interface GroupResult {
  group: JamfPatchRequirementGroup;
  tests: TestResult[];
  verdict: GroupVerdict;
}

export interface EvaluationResult {
  groups: GroupResult[];
  verdict: OverallVerdict;
}

function parseVersionTuple(value: string): number[] {
  return (value.match(/\d+/g) ?? []).map(Number);
}

function compareVersions(a: string, b: string): number {
  const av = parseVersionTuple(a);
  const bv = parseVersionTuple(b);
  const length = Math.max(av.length, bv.length);
  for (let i = 0; i < length; i++) {
    const diff = (av[i] ?? 0) - (bv[i] ?? 0);
    if (diff !== 0) return diff;
  }
  return 0;
}

function compareOperator(operator: string, actual: string, expected: string): boolean {
  const a = actual.toLowerCase();
  const e = expected.toLowerCase();

  switch (operator) {
    case "is":
      return a === e;
    case "is not":
      return a !== e;
    case "like":
      return a.includes(e);
    case "not like":
      return !a.includes(e);
    case "matches regex":
      try {
        return new RegExp(expected, "i").test(actual);
      } catch {
        return false;
      }
    case "does not match regex":
      try {
        return !new RegExp(expected, "i").test(actual);
      } catch {
        return true;
      }
    case "greater than":
      return compareVersions(actual, expected) > 0;
    case "greater than or equal":
      return compareVersions(actual, expected) >= 0;
    case "less than":
      return compareVersions(actual, expected) < 0;
    case "less than or equal":
      return compareVersions(actual, expected) <= 0;
    default:
      return false;
  }
}

export function evaluateTest(test: JamfPatchRequirementTest, facts: TestFacts): TestOutcome {
  if (test.type === "extensionAttribute") {
    if (!facts.extensionAttributeName || facts.extensionAttributeName.toLowerCase() !== test.name.toLowerCase()) {
      return "not_applicable";
    }
    return compareOperator(test.operator, facts.extensionAttributeValue, test.value) ? "pass" : "fail";
  }

  switch (test.name) {
    case "Application Bundle ID":
      return compareOperator(test.operator, facts.bundleId, test.value) ? "pass" : "fail";
    case "Application Title":
      return compareOperator(test.operator, facts.appName, test.value) ? "pass" : "fail";
    case "Application Version": {
      const shortMatches = compareOperator(test.operator, facts.shortVersion, test.value);
      const bundleMatches = compareOperator(test.operator, facts.bundleVersion, test.value);
      return shortMatches || bundleMatches ? "pass" : "fail";
    }
    default:
      // e.g. "Operating System Version" — no input field is collected for this,
      // so it's untestable rather than a hard pass or fail.
      return "not_applicable";
  }
}

function verdictForGroup(tests: TestResult[]): GroupVerdict {
  if (tests.some((t) => t.outcome === "fail")) return "not_matched";
  if (tests.some((t) => t.outcome === "pass")) return "matched";
  return "inconclusive";
}

export function evaluateRequirements(groups: JamfPatchRequirementGroup[], facts: TestFacts): EvaluationResult {
  const groupResults: GroupResult[] = groups.map((group) => {
    const tests = group.tests.map((test) => ({ test, outcome: evaluateTest(test, facts) }));
    return { group, tests, verdict: verdictForGroup(tests) };
  });

  let verdict: OverallVerdict = "not_matched";
  if (groupResults.some((g) => g.verdict === "matched")) {
    verdict = "matched";
  } else if (groupResults.some((g) => g.verdict === "inconclusive")) {
    verdict = "inconclusive";
  }

  return { groups: groupResults, verdict };
}
