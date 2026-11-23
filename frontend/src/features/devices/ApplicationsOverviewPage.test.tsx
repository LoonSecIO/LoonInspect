// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, useLocation } from "react-router";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { LocaleProvider } from "@/i18n/LocaleContext";
import { ApplicationsOverviewPage } from "./ApplicationsOverviewPage";
import { listApplications } from "./applicationsApi";
vi.mock("./applicationsApi", () => ({ listApplications: vi.fn() }));
vi.mock("@/features/mdm/api", () => ({ listSyncStatus: vi.fn(async () => []) }));
vi.mock("@/features/auth/store", () => ({ useHasPermission: () => true }));
vi.mock("@/features/catalog/DeviceScopeBuilder", () => ({ DeviceScopeBuilder: () => null }));
vi.mock("@/features/catalog/PatchPlanWorkspace", () => ({ PatchPlanWorkspace: () => null }));
const list = vi.mocked(listApplications);
function Location() { return <output aria-label="Location">{useLocation().search}</output>; }
beforeEach(() => list.mockResolvedValue({ items: [{ appHash: "a", name: "GitHub Desktop.app", bundleId: "com.github.GitHubClient", deviceCount: 10, versionCount: 2, matchedDeviceCount: 0, patchAvailableDeviceCount: 0 }], total: 201, page: 1, pageSize: 100, corpusAsOf: "2026-11-23", corpusRelease: "epoch" }));
afterEach(() => { cleanup(); vi.clearAllMocks(); });
it("composes severity/KEV with name and nested device scope, resets pagination, and preserves URL state", async () => {
  const scope = JSON.stringify({ match: "all", rules: [{ match: "any", rules: [{ field: "managed", value: "true" }] }] });
  render(<MemoryRouter initialEntries={[`/devices/applications?${new URLSearchParams({ deviceScope: scope, q: "GitHub", page: "2" })}`]}><LocaleProvider><ApplicationsOverviewPage /><Location /></LocaleProvider></MemoryRouter>);
  await screen.findByText("GitHub Desktop.app");
  expect(list).toHaveBeenLastCalledWith(expect.objectContaining({ q: "GitHub", page: 2, deviceScope: scope }));
  fireEvent.click(screen.getByLabelText("high"));
  await waitFor(() => expect(list).toHaveBeenLastCalledWith(expect.objectContaining({ page: 1, severities: ["high"], deviceScope: scope, q: "GitHub" })));
  fireEvent.click(screen.getByLabelText("critical"));
  fireEvent.click(screen.getByLabelText("Has KEV"));
  await waitFor(() => expect(list).toHaveBeenLastCalledWith(expect.objectContaining({ severities: ["critical", "high"], hasKev: true })));
  expect(new URLSearchParams(screen.getByLabelText("Location").textContent!).get("deviceScope")).toBe(scope);
  await screen.findByText("GitHub Desktop.app");
  fireEvent.click(screen.getByRole("button", { name: "Next" }));
  await waitFor(() => expect(list).toHaveBeenLastCalledWith(expect.objectContaining({ page: 2, hasKev: true })));
  fireEvent.click(screen.getByRole("button", { name: "Clear app filters" }));
  await waitFor(() => expect(list).toHaveBeenLastCalledWith(expect.objectContaining({ page: 1, q: undefined, severities: [], hasKev: false, deviceScope: scope })));
});
