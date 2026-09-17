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

const paths = (items: NavItem[]) => items.map((item) => item.to);
const posture = (items: NavItem[]) => items.find((item) => item.labelKey === "posture");
const settings = (items: NavItem[]) => items.find((item) => item.labelKey === "settings");
const settingsChildren = (items: NavItem[]) => settings(items)?.children?.map((child) => child.labelKey);

describe("visibleNavigation", () => {
  it("a viewer sees every fleet page and only the ungated Settings entries", () => {
    const items = visibleNavigation(VIEWER, NO_FLAGS);

    expect(paths(items)).toEqual(["/", "/devices", "/settings/my-account"]);
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
      "dataSharing",
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
      "myAccount"
    ]);
    // Both.
    expect(settingsChildren(visibleNavigation([PERMISSIONS.SYSTEM_READ], AI_ON))).toEqual([
      "dataSharing",
      "ai",
      "myAccount"
    ]);
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
      expect(posture(items)?.children?.map((child) => child.labelKey) ?? []).toEqual(listed ? ["vulnerabilities"] : []);
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
        "posture",
        "settings"
      ]);
    });
  });

  it("an unknown grant is ignored rather than trusted", () => {
    const items = visibleNavigation(["connection:read ", "CONNECTION:READ", "everything"], NO_FLAGS);
    expect(settingsChildren(items)).toEqual(["myAccount"]);
  });

  it("returns fresh arrays and leaves the declared tree untouched", () => {
    const before = JSON.stringify(navigationItems.map((item) => [item.to, item.children?.length]));
    const items = visibleNavigation(VIEWER, NO_FLAGS);

    expect(settings(items)).not.toBe(navigationItems[3]);
    expect(JSON.stringify(navigationItems.map((item) => [item.to, item.children?.length]))).toBe(before);
    expect(navigationItems[3].to).toBe("/settings/connections");
  });
});
