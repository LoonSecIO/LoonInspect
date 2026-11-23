// @vitest-environment jsdom
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, expect, it } from "vitest";
import { ApplicationRiskCells } from "./ApplicationRiskCells";
import type { Application, ApplicationRisk } from "./applicationsApi";
afterEach(cleanup);
const app: Application = { appHash: "a", name: "App", bundleId: "example", deviceCount: 4, versionCount: 2, matchedDeviceCount: 0, patchAvailableDeviceCount: 0 };
function view(risk: ApplicationRisk) { return render(<table><tbody><tr><ApplicationRiskCells app={{ ...app, vulnerabilities: risk }} /></tr></tbody></table>); }
it("shows partial coverage and the backend average without dividing by unassessed Macs", () => {
  view({ assessment: "partial", counts: { total: 10, critical: 0, high: 6, medium: 0, low: 4, kev: 1 }, assessedDeviceCount: 2, devicesWithUnknownBuilds: 2, assessedBuildCount: 3, unknownBuildCount: 2, averagePerAssessedDevice: 5 });
  expect(screen.getByText("10")).toBeTruthy();
  expect(screen.getByText("5.0")).toBeTruthy();
  expect(screen.getByText(/2\/4 devices assessed · partial coverage/)).toBeTruthy();
  expect(screen.getByText("KEV 1")).toBeTruthy();
});
it("renders unknown separately from an assessed zero", () => {
  const unknown: ApplicationRisk = { assessment: "unknown_app", counts: null, assessedDeviceCount: 0, devicesWithUnknownBuilds: 4, assessedBuildCount: 0, unknownBuildCount: 4, averagePerAssessedDevice: null };
  const rendered = view(unknown);
  expect(screen.getAllByText("—")).toHaveLength(2);
  rendered.unmount();
  view({ ...unknown, assessment: "covered", counts: { total: 0, critical: 0, high: 0, medium: 0, low: 0, kev: 0 }, assessedDeviceCount: 4, unknownBuildCount: 0, averagePerAssessedDevice: 0 });
  expect(screen.getByText("No known findings")).toBeTruthy();
  expect(screen.getByText("0.0")).toBeTruthy();
});
