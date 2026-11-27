import { describe, expect, it } from "vitest";
import { PERMISSIONS } from "@/features/auth/types";
import { navigationItems, visibleNavigation, type NavItem } from "./navigation";

const NO_FLAGS: ReadonlySet<string> = new Set();
const AI_ON: ReadonlySet<string> = new Set(["ai_features"]);
const VULN_ON: ReadonlySet<string> = new Set(["vulnerabilities"]);
/** What `corpusStore` hands the tree: a date, from a read that landed (#529). */
const ANSWERING: ReadonlySet<string> = new Set(["corpus"]);
const SILENT: ReadonlySet<string> = new Set();
const EVERYTHING = Object.values(PERMISSIONS);

/** The roles as `permissions.py` resolves them, reduced to what the tree reads. */
const VIEWER = [PERMISSIONS.DEVICE_READ, PERMISSIONS.APP_READ, PERMISSIONS.VULN_READ];
/** The Auditor, reduced the same way: the inventory floor plus the report's own `audit:read`. */
const AUDITOR = [...VIEWER, PERMISSIONS.AUDIT_READ];

const paths = (items: NavItem[]) => items.map((item) => item.to);
const posture = (items: NavItem[]) => items.find((item) => item.labelKey === "posture");
const settings = (items: NavItem[]) => items.find((item) => item.labelKey === "settings");
const settingsChildren = (items: NavItem[]) => settings(items)?.children?.map((child) => child.labelKey);

describe("visibleNavigation", () => {
  it("a viewer sees every fleet page and only the ungated Settings entries", () => {
    const items = visibleNavigation(VIEWER, NO_FLAGS);

    expect(paths(items)).toEqual(["/", "/devices", "/patch-plans", "/posture/macos", "/settings/my-account"]);
    // Devices' children carry no permission: the floor every role holds is enough.
    expect(items[1].children?.map((child) => child.to)).toEqual([
      "/devices/applications",
      "/devices/groups/cost",
      "/devices/changes"
    ]);
    // Support is gated on DEVICE_READ precisely so a viewer keeps it (#301).
    expect(settingsChildren(items)).toEqual(["myAccount", "support"]);
  });

  it("Settings is re-pointed at its first visible child when Connections is hidden", () => {
    // The parent's declared target is Connections, which a viewer cannot open; a link
    // there would be a nav item pointing at a refusal.
    expect(settings(visibleNavigation(VIEWER, NO_FLAGS))?.to).toBe("/settings/my-account");
    // An admin keeps the declared target.
    expect(settings(visibleNavigation(EVERYTHING, NO_FLAGS))?.to).toBe("/settings/connections");
  });

  it("no grants at all — and the pre-bootstrap undefined — still reach My Account", () => {
    for (const permissions of [[], undefined]) {
      const items = visibleNavigation(permissions, NO_FLAGS);
      expect(paths(items)).toEqual(["/", "/devices", "/settings/my-account"]);
      expect(settingsChildren(items)).toEqual(["myAccount"]);
    }
  });

  it("an admin sees the Settings entries in their declared order", () => {
    expect(settingsChildren(visibleNavigation(EVERYTHING, NO_FLAGS))).toEqual([
      "connections",
      "changeTracking",
      "featureFlags",
      "apiTokens",
      "aiConnections",
      "dataSharing",
      "aiActivity",
      "destinations",
      "accounts",
      "myAccount",
      "support"
    ]);
  });

  it("the AI entry needs the flag and the permission, and lands beside Data Sharing", () => {
    // The flag alone: the permission gate still holds.
    expect(settingsChildren(visibleNavigation(VIEWER, AI_ON))).toEqual(["myAccount", "support"]);
    // The permission alone: no top-level /ai exists until the switch is on (#319).
    expect(settingsChildren(visibleNavigation([PERMISSIONS.SYSTEM_READ], NO_FLAGS))).toEqual([
      "dataSharing",
      "aiActivity",
      "myAccount"
    ]);
    // Both.
    expect(settingsChildren(visibleNavigation([PERMISSIONS.SYSTEM_READ], AI_ON))).toEqual([
      "dataSharing",
      "aiActivity",
      "ai",
      "myAccount"
    ]);
  });

  it("AI connection setup remains reachable while AI is off, only for accounts that can mint tokens", () => {
    expect(settingsChildren(visibleNavigation([PERMISSIONS.TOKEN_CREATE], NO_FLAGS))).toEqual([
      "apiTokens", "aiConnections", "myAccount"
    ]);
    expect(settingsChildren(visibleNavigation(VIEWER, AI_ON))).not.toContain("aiConnections");
  });

  describe("Posture \u203a Vulnerabilities follows the corpus, with the flag as the override", () => {
    // The four combinations of the two inputs, and the failed read beside them. The entry is
    // listed when the data answers OR the flag overrides it — never only when both.
    it.each([
      ["neither", NO_FLAGS, SILENT, false],
      ["the corpus alone", NO_FLAGS, ANSWERING, true],
      ["the flag alone", VULN_ON, SILENT, true],
      ["both", VULN_ON, ANSWERING, true]
    ])("%s", (_name, flags, answering, listed) => {
      const items = visibleNavigation(VIEWER, flags, answering);
      expect(paths(items).includes("/posture/vulnerabilities")).toBe(listed);
      // A section follows its children: with the one child hidden, Posture goes with it.
      expect(posture(items)?.children?.map((child) => child.labelKey) ?? []).toEqual(
        listed ? ["vulnerabilities", "osPosture", "patchPolicy"] : ["osPosture", "patchPolicy"]
      );
    });

    it("a read that failed hides it, and is not the corpus being off", () => {
      // `corpusStore` answers the empty set for a read that failed AND for a corpus that is
      // genuinely silent — the entry is hidden either way, and this tree is handed no way to
      // tell them apart, so nothing drawn from it can report one as the other (#150).
      expect(paths(visibleNavigation(VIEWER, NO_FLAGS, SILENT))).not.toContain("/posture/vulnerabilities");
      // The default third argument is that same empty set: a session whose read has not
      // landed yet sees exactly what a silent one does, rather than a flash of the entry.
      expect(paths(visibleNavigation(VIEWER, NO_FLAGS))).not.toContain("/posture/vulnerabilities");
    });

    it("the permission still holds, and the section points at its one child", () => {
      // VULN_READ is the floor every role holds, so the case that proves the gate is an
      // account without it — which is no authenticated role today, and is the grant a new
      // role would have to be given deliberately.
      expect(paths(visibleNavigation([PERMISSIONS.DEVICE_READ], VULN_ON, ANSWERING))).not.toContain(
        "/posture/vulnerabilities"
      );
      expect(posture(visibleNavigation(EVERYTHING, NO_FLAGS, ANSWERING))?.to).toBe("/posture/vulnerabilities");
    });

    it("sits between Devices and Settings", () => {
      expect(visibleNavigation(EVERYTHING, NO_FLAGS, ANSWERING).map((item) => item.labelKey)).toEqual([
        "overview",
        "devices",
        "patchPlans",
        "posture",
        "settings"
      ]);
    });
  });

  describe("Posture \u203a Patch policy (#614, first slice)", () => {
    /** The registry key that listed it until 2026-11-24, when it was promoted and removed. */
    const RETIRED_FLAG: ReadonlySet<string> = new Set(["patch_policy"]);

    it("is listed last for every role, with no flag on and no corpus answering", () => {
      for (const permissions of [VIEWER, AUDITOR, EVERYTHING]) {
        const children = posture(visibleNavigation(permissions, NO_FLAGS, SILENT))?.children?.map((child) => child.labelKey) ?? [];
        expect(children.at(-1)).toBe("patchPolicy");
      }
      expect(posture(visibleNavigation(EVERYTHING, NO_FLAGS, ANSWERING))?.children?.map((child) => child.labelKey)).toEqual([
        "vulnerabilities",
        "compliance",
        "osPosture",
        "patchPolicy"
      ]);
    });

    it("a viewer with no corpus sees it beside macOS versions, and the section points at the first", () => {
      const section = posture(visibleNavigation(VIEWER, NO_FLAGS, SILENT));
      expect(section?.children?.map((child) => child.labelKey)).toEqual(["osPosture", "patchPolicy"]);
      expect(section?.to).toBe("/posture/macos");
    });

    it("needs app:read like its route", () => {
      const section = posture(visibleNavigation([PERMISSIONS.DEVICE_READ], NO_FLAGS));
      expect(section?.children?.map((child) => child.labelKey)).toEqual(["osPosture"]);
      expect(section?.to).toBe("/posture/macos");
    });

    it("the retired flag lists nothing: a stored patch_policy row changes no account's tree", () => {
      for (const permissions of [[], [PERMISSIONS.DEVICE_READ], VIEWER, AUDITOR, EVERYTHING]) {
        expect(visibleNavigation(permissions, RETIRED_FLAG, SILENT)).toEqual(visibleNavigation(permissions, NO_FLAGS, SILENT));
      }
    });
  });

  it("an auditor on a tenant with no corpus sees Posture \u203a Compliance alone", () => {
    // The case #536 is for: nothing answering and the flag off, so Vulnerabilities is hidden and the section
    // is not — it follows its children, and Compliance needs no corpus to answer for it.
    const section = posture(visibleNavigation(AUDITOR, NO_FLAGS, SILENT));

    expect(section?.children?.map((child) => child.labelKey)).toEqual(["compliance", "osPosture", "patchPolicy"]);
    // And re-pointed at it: the section's declared target is the child that went (#301).
    expect(section?.to).toBe("/posture/compliance");
    // `audit:read` is the gate, not the corpus: a viewer with both the flag and the data still lacks it.
    expect(paths(visibleNavigation(VIEWER, VULN_ON, ANSWERING))).not.toContain("/posture/compliance");
    const both = posture(visibleNavigation(EVERYTHING, NO_FLAGS, ANSWERING));
    expect(both?.children?.map((child) => child.labelKey)).toEqual(["vulnerabilities", "compliance", "osPosture", "patchPolicy"]);
  });

  describe("Settings › Intelligence Access (#622, #706)", () => {
    /** What `intelligenceStore` hands the tree when the page has something for this reader: the paid preview,
     *  contribution receipts, or a case to withdraw (its own tests pin which answers those are). */
    const OFFERED: ReadonlySet<string> = new Set(["intelligenceAccess"]);

    it("is listed only where the store says the page answers, right after Data Sharing", () => {
      expect(settingsChildren(visibleNavigation(EVERYTHING, NO_FLAGS))).not.toContain("intelligenceAccess");
      const children = settingsChildren(visibleNavigation(EVERYTHING, NO_FLAGS, OFFERED)) ?? [];
      expect(children[children.indexOf("dataSharing") + 1]).toBe("intelligenceAccess");
    });

    it("still needs SYSTEM_READ, and no feature flag can list it", () => {
      expect(settingsChildren(visibleNavigation(VIEWER, NO_FLAGS, OFFERED))).not.toContain("intelligenceAccess");
      const flagged: ReadonlySet<string> = new Set(["intelligenceAccess"]);
      expect(settingsChildren(visibleNavigation(EVERYTHING, flagged, SILENT))).not.toContain("intelligenceAccess");
    });
  });

  it("an unknown grant is ignored rather than trusted", () => {
    const items = visibleNavigation(["connection:read ", "CONNECTION:READ", "everything"], NO_FLAGS);
    expect(settingsChildren(items)).toEqual(["myAccount"]);
  });

  it("returns fresh arrays and leaves the declared tree untouched", () => {
    const before = JSON.stringify(navigationItems.map((item) => [item.to, item.children?.length]));
    const items = visibleNavigation(VIEWER, NO_FLAGS);

    expect(settings(items)).not.toBe(settings(navigationItems));
    expect(JSON.stringify(navigationItems.map((item) => [item.to, item.children?.length]))).toBe(before);
    expect(settings(navigationItems)?.to).toBe("/settings/connections");
  });
});

it("lists Patch Plans directly for inventory readers, including read-only roles, and requires both grants", () => {
  for (const permissions of [VIEWER, AUDITOR, EVERYTHING]) {
    expect(visibleNavigation(permissions, NO_FLAGS).find(item => item.labelKey === "patchPlans")?.to).toBe("/patch-plans");
  }
  for (const permissions of [[], [PERMISSIONS.APP_READ], [PERMISSIONS.DEVICE_READ]]) {
    expect(visibleNavigation(permissions, NO_FLAGS).find(item => item.labelKey === "patchPlans")).toBeUndefined();
  }
});
