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
const second: Device = { ...device, id: 8, externalId: "8", hostname: "Second Mac", departedAt: null };
const words = en.devices;
const answer = (items: Device[], total = items.length, corpusAsOf: string | null = null) => ({ items, total, corpusAsOf });
const requests = () => vi.mocked(apiRequest).mock.calls.map(([url]) => new URL(url, "https://example.invalid").searchParams);
const button = (name: string) => screen.getByRole("button", { name }) as HTMLButtonElement;
const refused = (status: number, sentence: string) => new ApiError(status, sentence, { detail: sentence });
const invalid = (message: string) => new ApiError(422, message, { detail: [{ msg: message }] });

type Props = Partial<Parameters<typeof DeviceTable>[0]>;
const extraColumn = { header: "Value", cell: (row: Device) => row.externalId };
function table(query: DeviceFilters, props: Props = {}) {
  return <MemoryRouter><LocaleProvider><DeviceTable query={query} onPageChange={vi.fn()} {...props} /></LocaleProvider></MemoryRouter>;
}
function watched() {
  const seen: DeviceTableAnswer[] = [];
  return { seen, actions: (state: DeviceTableAnswer) => { seen.push(state); return <button>Example action</button>; } };
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
  const { seen, actions } = watched();
  vi.mocked(apiRequest).mockResolvedValueOnce(answer([device], 4));
  const view = render(table({ page: 1 }, { actions }));
  await screen.findByRole("link", { name: device.hostname });
  expect(seen.at(-1)?.total).toBe(4);
  vi.mocked(apiRequest).mockRejectedValueOnce(refused(status, "The API's own sentence."));
  view.rerender(table({ page: 2 }, { actions }));
  await screen.findByText("The API's own sentence.");
  expect(seen.at(-1)?.total).toBeNull();
  expect(screen.queryByRole("link", { name: device.hostname })).toBeNull();
  expect(screen.queryByText(words.empty)).toBeNull();
  expect(screen.queryByText(words.total(4))).toBeNull();
  expect(screen.queryByRole("button", { name: words.next })).toBeNull();
  // The next question takes the refusal's line away while it is being asked (#479).
  vi.mocked(apiRequest).mockResolvedValueOnce(answer([device], 4));
  view.rerender(table({ page: 3 }, { actions }));
  expect(screen.queryByText("The API's own sentence.")).toBeNull();
  expect(screen.getByText(words.loading)).toBeTruthy();
  await screen.findByRole("link", { name: device.hostname });
});

it.each([
  ["a failure that is not a refusal", refused(500, "Internal detail nobody should read.")],
  ["a refusal that came with no sentence", new ApiError(409, null)],
  ["a validation refusal, whose detail is a list", invalid("Input should be greater than or equal to 1")],
])("keeps its own sentence for %s", async (_name, failure) => {
  vi.mocked(apiRequest).mockRejectedValue(failure);
  render(table({}));
  await screen.findByText(words.errorLoading);
  if (failure.detail) expect(screen.queryByText(failure.detail)).toBeNull();
  expect(screen.queryByText(words.empty)).toBeNull();
});

it("sends a page it cannot read as it was given, never page 1 in its place", async () => {
  vi.mocked(apiRequest).mockRejectedValue(invalid("Input should be a valid integer"));
  render(table({ page: Number("abc") }));
  await screen.findByText(words.errorLoading);
  expect(requests()[0].get("page")).toBe("NaN");
});

it("asks again for a different query and not for an equal one", async () => {
  vi.mocked(apiRequest).mockResolvedValue(answer([device], 4));
  const scope = { match: "all" as const, rules: [] };
  const view = render(table({ site: "Sample", deviceScope: scope, page: 1 }));
  await screen.findByRole("link", { name: device.hostname });
  view.rerender(table({ site: "Sample", deviceScope: { ...scope }, page: 1 }));
  expect(screen.queryByText(words.loading)).toBeNull();
  await new Promise(resolve => setTimeout(resolve, 400));
  expect(requests()).toHaveLength(1);
  const moved: DeviceFilters[] = [
    { site: "Sample", deviceScope: scope, page: 2 },
    { site: "Other", deviceScope: scope, page: 2 },
    { site: "Other", deviceScope: { match: "any", rules: [] }, page: 2 },
  ];
  for (const [index, query] of moved.entries()) {
    view.rerender(table(query));
    expect(screen.getByText(words.loading)).toBeTruthy();
    await waitFor(() => expect(requests()).toHaveLength(index + 2));
    await waitFor(() => expect(screen.queryByText(words.loading)).toBeNull());
  }
  expect(requests().map(params => [params.get("site"), params.get("deviceScope"), params.get("page")])).toEqual([
    ["Sample", JSON.stringify(scope), "1"],
    ["Sample", JSON.stringify(scope), "2"],
    ["Other", JSON.stringify(scope), "2"],
    ["Other", JSON.stringify({ match: "any", rules: [] }), "2"],
  ]);
});

it("asks once for the last of several quick changes", async () => {
  vi.mocked(apiRequest).mockResolvedValue(answer([]));
  const view = render(table({ q: "a" }));
  for (const q of ["ab", "abc"]) {
    await new Promise(resolve => setTimeout(resolve, 60));
    view.rerender(table({ q }));
  }
  await screen.findByText(words.empty);
  expect(requests().map(params => params.get("q"))).toEqual(["abc"]);
});

it("does not let a slow answer to the last question replace this one's", async () => {
  let late!: (value: ReturnType<typeof answer>) => void;
  vi.mocked(apiRequest)
    .mockReturnValueOnce(new Promise(resolve => { late = resolve; }))
    .mockResolvedValueOnce(answer([second]));
  const view = render(table({ page: 1 }));
  await waitFor(() => expect(requests()).toHaveLength(1));
  view.rerender(table({ page: 2 }));
  await screen.findByRole("link", { name: second.hostname });
  late(answer([device]));
  await new Promise(resolve => setTimeout(resolve, 50));
  expect(screen.queryByRole("link", { name: device.hostname })).toBeNull();
  expect(screen.getByRole("link", { name: second.hostname })).toBeTruthy();
});

it("hands the slot the answer above the table, and never the last question's count", async () => {
  vi.mocked(apiRequest).mockResolvedValue(answer([], 3, "2026-01-01T00:00:00Z"));
  const { seen, actions } = watched();
  const view = render(table({ page: 1 }, { actions }));
  expect(seen.at(-1)).toEqual({ corpusAsOf: null, total: null });
  await screen.findByText(words.total(3));
  expect(seen.at(-1)).toEqual({ corpusAsOf: "2026-01-01T00:00:00Z", total: 3 });
  expect(button("Example action").compareDocumentPosition(screen.getByRole("table")) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  expect(screen.getAllByRole("columnheader")).toHaveLength(9);
  view.rerender(table({ page: 2 }, { actions }));
  expect(seen.at(-1)).toEqual({ corpusAsOf: "2026-01-01T00:00:00Z", total: null });
});

it("renders the caller's column under its header, sends the whole query, and pages both ways", async () => {
  const query: DeviceFilters = { site: "Sample", deviceScope: { match: "all", rules: [] }, page: 2, pageSize: 1 };
  vi.mocked(apiRequest).mockResolvedValue(answer([device], 3));
  const onPageChange = vi.fn();
  const view = render(table(query, { extraColumn, onPageChange }));
  expect((await screen.findByRole("link", { name: device.hostname })).getAttribute("href")).toBe("/devices/7");
  expect((screen.getByRole("columnheader", { name: "Value" }) as HTMLTableCellElement).cellIndex).toBe(8);
  expect((screen.getByRole("cell", { name: "7" }) as HTMLTableCellElement).cellIndex).toBe(8);
  expect(Object.fromEntries(requests()[0])).toEqual({ site: "Sample", deviceScope: JSON.stringify(query.deviceScope), page: "2", pageSize: "1" });
  fireEvent.click(button(words.next));
  fireEvent.click(button(words.previous));
  expect(onPageChange.mock.calls).toEqual([[3], [1]]);
  // The pager stops at both ends of the three pages.
  expect([button(words.previous).disabled, button(words.next).disabled]).toEqual([false, false]);
  view.rerender(table({ ...query, page: 3 }, { extraColumn, onPageChange }));
  await waitFor(() => expect(requests()).toHaveLength(2));
  expect([button(words.previous).disabled, button(words.next).disabled]).toEqual([false, true]);
  view.rerender(table({ ...query, page: 1 }, { extraColumn, onPageChange }));
  await waitFor(() => expect(requests()).toHaveLength(3));
  expect([button(words.previous).disabled, button(words.next).disabled]).toEqual([true, false]);
});
