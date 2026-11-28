// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, expect, it, vi } from "vitest";
import { apiRequest } from "@/config/api";
import { LocaleProvider } from "@/i18n/LocaleContext";
import { DeviceTable } from "./DevicesPage";
import type { Device, DeviceFilters } from "./types";

vi.mock("@/config/api", async (importOriginal) => ({
  ...await importOriginal<typeof import("@/config/api")>(),
  apiRequest: vi.fn()
}));
afterEach(() => { cleanup(); vi.resetAllMocks(); });

const device: Device = {
  id: 7, externalId: "7", platform: "macos", mdmProvider: "jamf", mdmConnectionId: null,
  hostname: "Example Mac", serialNumber: "EXAMPLE", osVersion: null, site: null, managed: null,
  supervised: null, building: null, department: null, buildingId: null, departmentId: null,
  lastSeenAt: null, lastInventoryAt: null, lastCheckIn: null, departedAt: "2024-01-01T00:00:00Z"
};

function show(query: DeviceFilters = {}) {
  const onPageChange = vi.fn();
  render(<MemoryRouter><LocaleProvider><DeviceTable query={query} onPageChange={onPageChange}
    extraColumn={{ header: "Value", cell: row => row.externalId }}
    actions={() => <button>Example action</button>} />
  </LocaleProvider></MemoryRouter>);
  return onPageChange;
}

it("spans the extra column while loading, then shows an empty answer", async () => {
  vi.mocked(apiRequest).mockResolvedValue({ items: [], total: 0, corpusAsOf: null });
  show();
  expect(screen.getByText("Loading...").closest("td")?.colSpan).toBe(9);
  expect((await screen.findByText("No devices match these filters.")).closest("td")?.colSpan).toBe(9);
});

it("shows the load error without an empty answer or a pager", async () => {
  vi.mocked(apiRequest).mockRejectedValue(new Error("unavailable"));
  show();
  await screen.findByText("Failed to load devices.");
  expect(screen.queryByText("No devices match these filters.")).toBeNull();
  expect(screen.queryByRole("button", { name: "Next" })).toBeNull();
});

it("renders the optional column, actions and departed marker, and pages the query", async () => {
  const query: DeviceFilters = { site: "Sample", scope: { match: "all", rules: [] }, page: 2, pageSize: 1 };
  vi.mocked(apiRequest).mockResolvedValue({ items: [device], total: 4, corpusAsOf: null });
  const onPageChange = show(query);
  expect((await screen.findByRole("link", { name: device.hostname })).getAttribute("href")).toBe("/devices/7");
  expect(screen.getByText("Left the fleet")).toBeDefined();
  expect(screen.getByRole("columnheader", { name: "Value" }).closest("th")?.cellIndex)
    .toBe(screen.getByRole("cell", { name: "7" }).closest("td")?.cellIndex);
  expect(screen.getByRole("button", { name: "Example action" })).toBeDefined();
  const [url] = vi.mocked(apiRequest).mock.calls[0];
  const params = new URL(url, "https://example.invalid").searchParams;
  expect(Object.fromEntries(params)).toEqual({ site: "Sample", scope: JSON.stringify(query.scope), page: "2", pageSize: "1" });
  fireEvent.click(screen.getByRole("button", { name: "Next" }));
  expect(onPageChange).toHaveBeenCalledWith(3);
});
