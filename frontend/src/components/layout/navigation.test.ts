import { describe, expect, it } from "vitest";
import { PERMISSIONS } from "@/features/auth/types";
import { navigationItems, visibleNavigation, type NavItem } from "./navigation";

const NO_FLAGS: ReadonlySet<string> = new Set();
const AI_ON: ReadonlySet<string> = new Set(["ai_features"]);
const EVERYTHING = Object.values(PERMISSIONS);

/** The roles as `permissions.py` resolves them, reduced to what the tree reads. */
const VIEWER = [PERMISSIONS.DEVICE_READ, PERMISSIONS.APP_READ, PERMISSIONS.VULN_READ];

const paths = (items: NavItem[]) => items.map((item) => item.to);
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

  it("an unknown grant is ignored rather than trusted", () => {
    const items = visibleNavigation(["connection:read ", "CONNECTION:READ", "everything"], NO_FLAGS);
    expect(settingsChildren(items)).toEqual(["myAccount"]);
  });

  it("returns fresh arrays and leaves the declared tree untouched", () => {
    const before = JSON.stringify(navigationItems.map((item) => [item.to, item.children?.length]));
    const items = visibleNavigation(VIEWER, NO_FLAGS);

    expect(settings(items)).not.toBe(navigationItems[2]);
    expect(JSON.stringify(navigationItems.map((item) => [item.to, item.children?.length]))).toBe(before);
    expect(navigationItems[2].to).toBe("/settings/connections");
  });
});
