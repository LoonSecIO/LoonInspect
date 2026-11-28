// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, expect, it, vi } from "vitest";
import { ApiError, apiRequest } from "@/config/api";
import { en } from "@/i18n/en";
import { LocaleProvider } from "@/i18n/LocaleContext";
import { DeviceTable, type DeviceTableAnswer } from "./DevicesPage";
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
const words = en.devices;
const answer = (items: Device[], total = items.length, corpusAsOf: string | null = null) => ({ items, total, corpusAsOf });
const requests = () => vi.mocked(apiRequest).mock.calls.map(([url]) => new URL(url, "https://example.invalid").searchParams);

type Props = Partial<Parameters<typeof DeviceTable>[0]>;
const extraColumn = { header: "Value", cell: (row: Device) => row.externalId };
function table(query: DeviceFilters, props: Props = {}) {
  return <MemoryRouter><LocaleProvider><DeviceTable query={query} onPageChange={vi.fn()} {...props} /></LocaleProvider></MemoryRouter>;
}

it("says it is asking before it says there is nothing, across the caller's column", async () => {
  vi.mocked(apiRequest).mockResolvedValue(answer([]));
  render(table({}, { extraColumn }));
  expect(screen.getByText(words.loading).closest("td")?.colSpan).toBe(9);
  expect(screen.queryByText(words.empty)).toBeNull();
  expect((await screen.findByText(words.empty)).closest("td")?.colSpan).toBe(9);
  expect(screen.queryByText(words.loading)).toBeNull();
});

it("is the Devices page's table when no column and no slot are passed", async () => {
  vi.mocked(apiRequest).mockResolvedValue(answer([device]));
  render(table({}));
  expect(screen.getByText(words.loading).closest("td")?.colSpan).toBe(8);
  await screen.findByRole("link", { name: device.hostname });
  expect(screen.getAllByRole("columnheader")).toHaveLength(8);
  expect(screen.getAllByRole("cell")).toHaveLength(8);
  expect(screen.getByText(words.leftChip).tagName).toBe("SPAN");
});

it.each([408, 409, 422])("prints a %i refusal in the API's own words, with no rows, count or pager", async (status) => {
  vi.mocked(apiRequest).mockResolvedValueOnce(answer([device], 4));
  const view = render(table({ page: 1 }));
  await screen.findByRole("link", { name: device.hostname });
  vi.mocked(apiRequest).mockRejectedValueOnce(new ApiError(status, "The API's own sentence."));
  view.rerender(table({ page: 2 }));
  await screen.findByText("The API's own sentence.");
  expect(screen.queryByRole("link", { name: device.hostname })).toBeNull();
  expect(screen.queryByText(words.empty)).toBeNull();
  expect(screen.queryByText(words.total(4))).toBeNull();
  expect(screen.queryByRole("button", { name: words.next })).toBeNull();
});

it("keeps its own sentence for a failure that is not a refusal", async () => {
  vi.mocked(apiRequest).mockRejectedValue(new ApiError(500, "Internal detail nobody should read."));
  render(table({}));
  await screen.findByText(words.errorLoading);
  expect(screen.queryByText("Internal detail nobody should read.")).toBeNull();
  expect(screen.queryByText(words.empty)).toBeNull();
});

it("asks again for a different query and not for an equal one", async () => {
  vi.mocked(apiRequest).mockResolvedValue(answer([device], 4));
  const scope = { match: "all" as const, rules: [] };
  const view = render(table({ site: "Sample", scope, page: 1 }));
  await screen.findByRole("link", { name: device.hostname });
  view.rerender(table({ site: "Sample", scope: { ...scope }, page: 1 }));
  expect(screen.queryByText(words.loading)).toBeNull();
  await new Promise(resolve => setTimeout(resolve, 400));
  expect(requests()).toHaveLength(1);
  view.rerender(table({ site: "Sample", scope, page: 2 }));
  expect(screen.getByText(words.loading)).toBeTruthy();
  await waitFor(() => expect(requests().map(params => params.get("page"))).toEqual(["1", "2"]));
  await waitFor(() => expect(screen.queryByText(words.loading)).toBeNull());
});

it("hands the slot the answer above the table, and never the last question's count", async () => {
  vi.mocked(apiRequest).mockResolvedValue(answer([], 3, "2026-01-01T00:00:00Z"));
  const seen: DeviceTableAnswer[] = [];
  const actions = (state: DeviceTableAnswer) => { seen.push(state); return <button>Example action</button>; };
  const view = render(table({ page: 1 }, { actions }));
  expect(seen.at(-1)).toEqual({ corpusAsOf: null, total: null });
  await screen.findByText(words.total(3));
  expect(seen.at(-1)).toEqual({ corpusAsOf: "2026-01-01T00:00:00Z", total: 3 });
  const slot = screen.getByRole("button", { name: "Example action" });
  expect(slot.compareDocumentPosition(screen.getByRole("table")) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  expect(screen.getAllByRole("columnheader")).toHaveLength(9);
  view.rerender(table({ page: 2 }, { actions }));
  expect(seen.at(-1)).toEqual({ corpusAsOf: "2026-01-01T00:00:00Z", total: null });
});

it("renders the caller's column under its header, sends the whole query, and pages both ways", async () => {
  const query: DeviceFilters = { site: "Sample", scope: { match: "all", rules: [] }, page: 2, pageSize: 1 };
  vi.mocked(apiRequest).mockResolvedValue(answer([device], 4));
  const onPageChange = vi.fn();
  render(table(query, { extraColumn, onPageChange }));
  expect((await screen.findByRole("link", { name: device.hostname })).getAttribute("href")).toBe("/devices/7");
  const header = screen.getByRole("columnheader", { name: "Value" }) as HTMLTableCellElement;
  expect(header.cellIndex).toBe(8);
  expect((screen.getByRole("cell", { name: "7" }) as HTMLTableCellElement).cellIndex).toBe(8);
  expect(Object.fromEntries(requests()[0])).toEqual({ site: "Sample", scope: JSON.stringify(query.scope), page: "2", pageSize: "1" });
  fireEvent.click(screen.getByRole("button", { name: words.next }));
  fireEvent.click(screen.getByRole("button", { name: words.previous }));
  expect(onPageChange.mock.calls).toEqual([[3], [1]]);
});
