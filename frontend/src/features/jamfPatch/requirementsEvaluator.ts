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

// Mirrors backend/app/mdm/patch/requirements.py — the same rule the device process applies.
// `null` means the operator is not one we know: not applicable rather than a failure.
function compareOperator(operator: string, actual: string, expected: string): boolean | null {
  const a = actual.trim().toLowerCase();
  const e = expected.trim().toLowerCase();

  switch (operator) {
    case "is":
      return a === e;
    case "is not":
      return a !== e;
    case "like":
    case "has":
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
      return null;
  }
}

function outcomeOf(result: boolean | null): TestOutcome {
  if (result === null) return "not_applicable";
  return result ? "pass" : "fail";
}

export function evaluateTest(test: JamfPatchRequirementTest, facts: TestFacts): TestOutcome {
  if (test.type === "extensionAttribute") {
    if (!facts.extensionAttributeName || facts.extensionAttributeName.toLowerCase() !== test.name.toLowerCase()) {
      return "not_applicable";
    }
    return outcomeOf(compareOperator(test.operator, facts.extensionAttributeValue, test.value));
  }

  switch (test.name) {
    case "Application Bundle ID":
      return outcomeOf(compareOperator(test.operator, facts.bundleId, test.value));
    case "Application Title":
      return outcomeOf(compareOperator(test.operator, facts.appName, test.value));
    case "Application Version": {
      const results = [facts.shortVersion, facts.bundleVersion]
        .filter((version) => version !== "")
        .map((version) => compareOperator(test.operator, version, test.value));
      if (results.length === 0 || results.every((result) => result === null)) return "not_applicable";
      return results.some((result) => result === true) ? "pass" : "fail";
    }
    default:
      // e.g. "Operating System Version" — no input field is collected for this,
      // so it's untestable rather than a hard pass or fail.
      return "not_applicable";
  }
}

// A group is matched only when every test passed; anything not applicable leaves it
// inconclusive, and one failure rules it out. Same rule as the backend.
function verdictForGroup(tests: TestResult[]): GroupVerdict {
  if (tests.length === 0) return "not_matched";
  if (tests.some((t) => t.outcome === "fail")) return "not_matched";
  if (tests.some((t) => t.outcome === "not_applicable")) return "inconclusive";
  return "matched";
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
