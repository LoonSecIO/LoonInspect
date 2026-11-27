import { expect, it } from "vitest";
import { applicationFilters, applicationScopeFromParams, fleetCatalogHref, patchPlanHref, planInventoryHref } from "./patchPlanNavigation";
import type { PatchPlan } from "./patchPlanTypes";

it("carries nested device scope and every application risk filter into a selected plan", () => {
  const scope = JSON.stringify({ match: "all", rules: [{ match: "any", rules: [{ field: "managed", value: "true" }] }] });
  const params = new URLSearchParams({ deviceScope: scope, q: "Browser", hasKev: "true", page: "9", plan: "old-plan" });
  params.append("severity", "critical"); params.append("severity", "high");
  const url = new URL(patchPlanHref(params, ["a", "b", "a"]), "https://example.invalid");
  expect(url.pathname).toBe("/patch-plans");
  expect(url.searchParams.getAll("appHash")).toEqual(["a", "b"]);
  expect(url.searchParams.getAll("severity")).toEqual(["critical", "high"]);
  expect(url.searchParams.get("deviceScope")).toBe(scope);
  expect(applicationScopeFromParams(url.searchParams)).toEqual({ q: "Browser", severities: ["critical", "high"], hasKev: true });
  expect(url.searchParams.has("plan")).toBe(false); expect(url.searchParams.has("page")).toBe(false);
});

it("keeps saved-plan links and returns to the saved evidence's scope", () => {
  expect(new URL(patchPlanHref(new URLSearchParams({ plan: "saved", page: "2" })), "https://example.invalid").searchParams.get("plan")).toBe("saved");
  const scope = { match: "all", connectionId: 7, rules: [] };
  const plan = { snapshot: { scope, applicationScope: { q: "Browser", severities: ["high", "critical"], hasKev: true } } } as unknown as PatchPlan;
  const url = new URL(planInventoryHref(plan), "https://example.invalid");
  expect(url.pathname).toBe("/devices/applications");
  expect(JSON.parse(url.searchParams.get("deviceScope")!)).toEqual(scope);
  expect(url.searchParams.getAll("severity")).toEqual(["high", "critical"]);
  expect(url.searchParams.get("q")).toBe("Browser"); expect(url.searchParams.get("hasKev")).toBe("true");
  expect(applicationFilters(new URLSearchParams("appHash=x&plan=saved&page=2")).toString()).toBe("");
});

it("opens the Fleet catalog tab on the address's device filter, unparsed, and nothing else", () => {
  const scope = JSON.stringify({ match: "all", connectionId: 3, rules: [{ field: "inventory", operator: "within", value: "30", key: "" }] });
  const params = new URLSearchParams({ deviceScope: scope, q: "Browser", severity: "high", hasKev: "true", page: "2", plan: "saved" });
  expect(fleetCatalogHref(params)).toBe(`/devices/applications/fleet-catalog?${new URLSearchParams({ deviceScope: scope })}`);
  expect(fleetCatalogHref(new URLSearchParams("deviceScope=%7Bbroken"))).toBe("/devices/applications/fleet-catalog?deviceScope=%7Bbroken");
  expect(fleetCatalogHref(new URLSearchParams("q=Browser&severity=high"))).toBe("/devices/applications/fleet-catalog");
});
