/**
 * Parity with `backend/app/mdm/patch/requirements.py` (#138, #285).
 *
 * The evaluator is a hand-maintained mirror of the backend's, and it encodes rulings Kyle
 * typed on #65/#66 — so these are contract tests: the cases are the backend suite's own
 * (`backend/tests/test_patch_requirements.py`, literal titles from the catalog synced
 * 2026-08-22), replayed against the mirror. Where the mirror diverges by design — it has
 * no OS-version or platform fact to read, and its one extension-attribute field stands
 * for the whole map — the divergence is named in the test rather than papered over.
 */

import { describe, expect, it } from "vitest";
import { evaluateRequirements, evaluateTest, type TestFacts } from "@/features/jamfPatch/requirementsEvaluator";
import type { JamfPatchRequirementGroup, JamfPatchRequirementTest } from "@/features/jamfPatch/types";

const recon = (name: string, operator: string, value: string): JamfPatchRequirementTest => ({
  name,
  operator,
  value,
  type: "recon"
});
const attribute = (name: string, operator: string, value: string): JamfPatchRequirementTest => ({
  name,
  operator,
  value,
  type: "extensionAttribute"
});
const group = (...tests: JamfPatchRequirementTest[]): JamfPatchRequirementGroup => ({ operator: "and", tests });

const facts = (over: Partial<TestFacts> = {}): TestFacts => ({
  appName: "",
  bundleId: "",
  shortVersion: "",
  bundleVersion: "",
  extensionAttributeName: "",
  extensionAttributeValue: "",
  ...over
});

const BUNDLE_ID = "Application Bundle ID";
const TITLE = "Application Title";
const VERSION = "Application Version";

// The literal titles the backend suite pins.
const ONEPASSWORD_4 = [
  group(
    recon(BUNDLE_ID, "is", "com.agilebits.onepassword4"),
    recon(VERSION, "like", "4."),
    recon(BUNDLE_ID, "is", "com.agilebits.onepassword4"),
    recon(VERSION, "not like", "5.4.")
  )
];
const ONEPASSWORD_6 = [group(recon(BUNDLE_ID, "is", "com.agilebits.onepassword4"), recon(VERSION, "like", "6."))];
const ABLETON_LIVE_LITE = [
  group(recon(BUNDLE_ID, "is", "com.ableton.live"), recon(TITLE, "has", "Ableton Live 10 Lite.app")),
  group(recon(TITLE, "has", "Ableton Live 11 Lite.app")),
  group(recon(TITLE, "has", "Ableton Live 12 Lite.app"))
];
const FIREFOX = [group(attribute("jamf-patch-mozilla-firefox", "is not", ""))];
const MACOS_CATALINA = [
  group(
    recon("Operating System Version", "greater than or equal", "10.15"),
    recon("Operating System Version", "less than", "10.16")
  )
];

const onePassword = (version: string): TestFacts =>
  facts({ appName: "1Password.app", bundleId: "com.agilebits.onepassword4", shortVersion: version });

/** The sign of `compareVersions(a, b)`, read through the ordered operators it backs. */
function versionSign(a: string, b: string): -1 | 0 | 1 {
  const lt = evaluateTest(recon(VERSION, "less than", b), facts({ shortVersion: a })) === "pass";
  const gt = evaluateTest(recon(VERSION, "greater than", b), facts({ shortVersion: a })) === "pass";
  return gt ? 1 : lt ? -1 : 0;
}

describe("version comparison — digit runs as integer tuples", () => {
  it.each([
    ["4.2", "4.2.0", 0],
    ["7.0.5 (81138)", "7.1.5 (84650)", -1],
    ["02.05.00.66", "02.08.02.61", -1],
    ["27.0", "26.6.2", 1],
    ["2022.6.10", "2026.2.0", -1],
    ["11.30.2", "11.31.1", -1]
  ] as const)("%s vs %s", (a, b, sign) => {
    expect(versionSign(a, b)).toBe(sign);
  });

  it("does not compare versions as strings: 10.2 is older than 10.10", () => {
    expect(versionSign("10.2", "10.10")).toBe(-1);
    expect(versionSign("10.10", "10.9")).toBe(1);
    expect(versionSign("2.0", "10.0")).toBe(-1);
  });
});

describe("operators — parity with app.mdm.patch.requirements.compare", () => {
  it("is / is not are case-insensitive equality", () => {
    expect(evaluateTest(recon(BUNDLE_ID, "is", "com.apple.safari"), facts({ bundleId: "com.Apple.Safari" }))).toBe("pass");
    expect(evaluateTest(recon(BUNDLE_ID, "is not", "com.apple.safari"), facts({ bundleId: "com.apple.safari" }))).toBe("fail");
  });

  it("like is a substring test, which the catalog relies on", () => {
    // "5.4.3" is like "4." — the reason 1Password 4 also says not like "5.4.".
    expect(evaluateTest(recon(VERSION, "like", "4."), facts({ shortVersion: "5.4.3" }))).toBe("pass");
    expect(evaluateTest(recon(VERSION, "not like", "5.4."), facts({ shortVersion: "5.4.3" }))).toBe("fail");
    expect(evaluateTest(recon(TITLE, "has", "Ableton Live 11 Lite.app"), facts({ appName: "Ableton Live 11 Lite.app" }))).toBe(
      "pass"
    );
  });

  it("regex operators, and an invalid pattern that can never match", () => {
    expect(evaluateTest(recon(VERSION, "matches regex", "^4\\.2\\."), facts({ shortVersion: "4.2.0" }))).toBe("pass");
    expect(evaluateTest(recon(VERSION, "does not match regex", "^4\\.2\\."), facts({ shortVersion: "4.2.0" }))).toBe("fail");
    expect(evaluateTest(recon(VERSION, "matches regex", "["), facts({ shortVersion: "anything" }))).toBe("fail");
    expect(evaluateTest(recon(VERSION, "does not match regex", "["), facts({ shortVersion: "anything" }))).toBe("pass");
  });

  it("ordered operators compare versions", () => {
    expect(evaluateTest(recon(VERSION, "greater than or equal", "10.15"), facts({ shortVersion: "10.15.7" }))).toBe("pass");
    expect(evaluateTest(recon(VERSION, "less than", "10.16"), facts({ shortVersion: "10.15.7" }))).toBe("pass");
    expect(evaluateTest(recon(VERSION, "greater than", "26.0"), facts({ shortVersion: "26.0" }))).toBe("fail");
    expect(evaluateTest(recon(VERSION, "less than or equal", "26.0"), facts({ shortVersion: "26.0" }))).toBe("pass");
  });

  it("an unknown operator is not applicable, never a failure", () => {
    expect(evaluateTest(recon(BUNDLE_ID, "is within", "x"), facts({ bundleId: "x" }))).toBe("not_applicable");
  });
});

describe("evaluateTest — one criterion against one app", () => {
  it("bundle id: pass, fail, and unknown when the field is empty", () => {
    const test = ONEPASSWORD_4[0].tests[0];
    expect(evaluateTest(test, onePassword("4.4.3"))).toBe("pass");
    expect(evaluateTest(test, facts({ bundleId: "com.agilebits.onepassword7" }))).toBe("fail");
    // The drift the parity suite caught (#285): an empty field is a fact nobody stated,
    // as it is for `Facts(bundle_id=None)` on the backend — not a bundle id of "".
    expect(evaluateTest(test, facts())).toBe("not_applicable");
    expect(evaluateTest(recon(TITLE, "is", "Safari.app"), facts())).toBe("not_applicable");
  });

  it("version passes if any version string does — the connector's slot does not matter", () => {
    const test = recon(VERSION, "like", "126.0.");
    expect(evaluateTest(test, facts({ shortVersion: "6478.127", bundleVersion: "126.0.6478.127" }))).toBe("pass");
    expect(evaluateTest(test, facts({ shortVersion: "6478.127" }))).toBe("fail");
    expect(evaluateTest(test, facts())).toBe("not_applicable");
  });

  it("an extension attribute the form does not carry is not applicable; an empty value is a value", () => {
    const test = FIREFOX[0].tests[0];
    expect(evaluateTest(test, facts())).toBe("not_applicable");
    expect(evaluateTest(test, facts({ extensionAttributeName: "some-other-attribute", extensionAttributeValue: "1" }))).toBe(
      "not_applicable"
    );
    // Looked up case-insensitively, like the backend's map.
    expect(evaluateTest(test, facts({ extensionAttributeName: "JAMF-PATCH-MOZILLA-FIREFOX", extensionAttributeValue: "154.0" }))).toBe(
      "pass"
    );
    // Jamf's empty string is a reported value, not an unknown: `is not ""` fails on it.
    expect(evaluateTest(test, facts({ extensionAttributeName: "jamf-patch-mozilla-firefox", extensionAttributeValue: "" }))).toBe(
      "fail"
    );
  });

  it("facts the form does not collect are not applicable — by design, not by drift", () => {
    // The backend evaluates OS version and platform when told them; the hand-check has
    // no field for either, so a device-level title cannot be judged here at all.
    const [ge, lt] = MACOS_CATALINA[0].tests;
    expect(evaluateTest(ge, facts())).toBe("not_applicable");
    expect(evaluateTest(lt, facts())).toBe("not_applicable");
    expect(evaluateTest(recon("Platform", "is", "Mac"), facts())).toBe("not_applicable");
    expect(evaluateTest(recon("Computer Name", "is", "x"), facts())).toBe("not_applicable");
  });
});

describe("groups and verdicts", () => {
  it("a group matches only when every test passes", () => {
    const firefox = group(recon(BUNDLE_ID, "is", "org.mozilla.firefox"), FIREFOX[0].tests[0]);
    const withBundle = facts({ bundleId: "org.mozilla.firefox" });
    expect(evaluateRequirements([firefox], withBundle).verdict).toBe("inconclusive"); // pass + not applicable
    const carried = facts({
      bundleId: "org.mozilla.firefox",
      extensionAttributeName: "jamf-patch-mozilla-firefox",
      extensionAttributeValue: "154.0"
    });
    expect(evaluateRequirements([firefox], carried).verdict).toBe("matched");
    expect(evaluateRequirements([firefox], facts({ bundleId: "com.google.Chrome" })).verdict).toBe("not_matched");
    expect(evaluateRequirements([group()], withBundle).groups[0].verdict).toBe("not_matched");
  });

  it("any matched group matches the title", () => {
    const lite = facts({ appName: "Ableton Live 12 Lite.app", bundleId: "com.ableton.live", shortVersion: "12.1" });
    const suite = facts({ appName: "Ableton Live 11 Suite.app", bundleId: "com.ableton.live", shortVersion: "11.3" });
    expect(evaluateRequirements(ABLETON_LIVE_LITE, lite).verdict).toBe("matched");
    expect(evaluateRequirements(ABLETON_LIVE_LITE, suite).verdict).toBe("not_matched");
  });

  it("inconclusive only when nothing matched and something could not be judged", () => {
    expect(evaluateRequirements(FIREFOX, facts({ bundleId: "org.mozilla.firefox" })).verdict).toBe("inconclusive");
    expect(evaluateRequirements([], facts()).verdict).toBe("not_matched");
  });

  it("1Password 4 versus 5: the substring leak the catalog guards against", () => {
    expect(evaluateRequirements(ONEPASSWORD_4, onePassword("4.4.3")).verdict).toBe("matched");
    expect(evaluateRequirements(ONEPASSWORD_4, onePassword("5.4.3")).verdict).toBe("not_matched"); // like "4." but not like "5.4."
    expect(evaluateRequirements(ONEPASSWORD_6, onePassword("6.8.9")).verdict).toBe("matched");
    expect(evaluateRequirements(ONEPASSWORD_6, onePassword("4.4.3")).verdict).toBe("not_matched");
  });

  it("a blank form is inconclusive, not not-matched", () => {
    // What the admin sees before typing a character. Before #285 this read "not matched".
    expect(evaluateRequirements(ONEPASSWORD_4, facts()).verdict).toBe("inconclusive");
    expect(evaluateRequirements(ABLETON_LIVE_LITE, facts()).verdict).toBe("inconclusive");
  });

  it("carries every group's verdict and every test's outcome for the panel to show", () => {
    const result = evaluateRequirements(ONEPASSWORD_4, onePassword("5.4.3"));
    expect(result.groups).toHaveLength(1);
    expect(result.groups[0].tests.map((t) => t.outcome)).toEqual(["pass", "pass", "pass", "fail"]);
    expect(result.groups[0].verdict).toBe("not_matched");
  });
});
