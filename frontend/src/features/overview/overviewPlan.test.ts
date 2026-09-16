import { describe, expect, it } from "vitest";
import { planOverview } from "./overviewPlan";

/** The built-in roles, transcribed from `backend/app/core/permissions.py` — this lane
 *  cannot reach the enum, so the copy is part of what is under test: a role whose grants
 *  moved shows up here as a failure rather than as a viewer staring at a gap. */
const INVENTORY_READ = ["device:read", "app:read", "vuln:read"];
const SHARED = ["connection:read", "audit:read", "token:create", "destination:read", "system:read"];
const VIEWER = INVENTORY_READ;
const ANALYST = [...INVENTORY_READ, ...SHARED, "patch:catalog-sync", "device:sync"];
const AUDITOR = [...INVENTORY_READ, ...SHARED, "account:read"];

describe("planOverview", () => {
  it("tells the pipeline story to every role holding destination:read", () => {
    for (const role of [ANALYST, AUDITOR]) {
      expect(planOverview(role)).toEqual({ story: "pipeline", tiles: [] });
    }
  });

  it("tells a viewer the inventory story, in laid-out order", () => {
    expect(planOverview(VIEWER)).toEqual({ story: "inventory", tiles: ["fleet", "hygiene", "catalog", "topApps"] });
  });

  it("does not change what a viewer is shown when connection:read is added", () => {
    // Nothing on this board reads `/api/mdm/status`; the fleet count comes from
    // `/api/devices`, which is inventory-read.
    expect(planOverview([...VIEWER, "connection:read"]).tiles).toEqual(planOverview(VIEWER).tiles);
  });

  it("drops the tiles whose source the account cannot read", () => {
    expect(planOverview(["device:read"]).tiles).toEqual(["fleet", "hygiene"]);
    expect(planOverview(["app:read"]).tiles).toEqual(["catalog", "topApps"]);
  });

  it("plans no tiles for a principal with neither the pipeline nor any inventory read", () => {
    // Not an empty board: the page owes that session a sentence saying so (#150). The last
    // one also pins that the decision reads permissions and never a role name.
    expect(planOverview([])).toEqual({ story: "inventory", tiles: [] });
    expect(planOverview(["audit:read", "system:read"]).tiles).toEqual([]);
    expect(planOverview(["viewer"]).tiles).toEqual([]);
  });
});
