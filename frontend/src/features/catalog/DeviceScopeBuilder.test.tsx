// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { apiRequest } from "@/config/api";
import { DeviceScopeBuilder } from "./DeviceScopeBuilder";
import { defaultScope, newRule } from "./deviceScope";

vi.mock("@/config/api", async original => ({ ...await original<typeof import("@/config/api")>(), apiRequest: vi.fn() }));
vi.mock("@/features/auth/store", () => ({ useAuthStore: () => ({ id: "operator", tenant: { id: "org" } }) }));
const request = vi.mocked(apiRequest);
beforeEach(() => {
  localStorage.clear();
  request.mockImplementation(async path => path.includes("scope-options") ? { devices: 42, connections: [{ id: 7, name: "Jamf" }], groups: [], attributes: [] }
    : { available: true, providers: [{ provider: "ollama", model: "qwen3.8:27b-mlx" }] });
});
afterEach(() => { cleanup(); vi.clearAllMocks(); });
function setup() {
  const change = vi.fn();
  render(<MemoryRouter><DeviceScopeBuilder value={JSON.stringify(defaultScope)} onChange={change} /></MemoryRouter>);
  return change;
}
describe("device scope builder", () => {
  it("edits indented groups and applies only on demand", async () => {
    const change = setup();
    await screen.findByText(/42 current Jamf Macs/);
    fireEvent.click(screen.getByRole("button", { name: "Add condition" }));
    fireEvent.click(screen.getByRole("button", { name: "Add group" }));
    fireEvent.change(screen.getByLabelText("Condition 2.1 field"), { target: { value: "contact" } });
    expect((screen.getByLabelText("Group 2 operator") as HTMLSelectElement).value).toBe("any");
    expect(change).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "Apply device filter" }));
    expect(JSON.parse(change.mock.calls[0][0])).toEqual({ match: "all", rules: [newRule(), { match: "any", rules: [newRule("contact")] }] });
    fireEvent.change(screen.getByLabelText("Condition 2.1 comparison"), { target: { value: "unknown" } });
    fireEvent.click(screen.getByRole("button", { name: "Apply device filter" }));
    expect(JSON.parse(change.mock.calls[1][0]).rules[1].rules[0]).toEqual({ ...newRule("contact"), operator: "unknown", value: "" });
    fireEvent.click(screen.getByLabelText("Remove condition 2.1"));
    expect((screen.getByRole("button", { name: "Apply device filter" }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(screen.getByLabelText("Remove group 2"));
    expect((screen.getByRole("button", { name: "Apply device filter" }) as HTMLButtonElement).disabled).toBe(false);
  });
  it("keeps imported JSON and named filters as drafts", async () => {
    const change = setup();
    await screen.findByText(/42 current Jamf Macs/);
    fireEvent.click(screen.getByText("Save or inspect scope JSON"));
    fireEvent.change(screen.getByLabelText("Import scope JSON"), { target: { value: JSON.stringify({ match: "any", rules: [newRule()] }) } });
    fireEvent.click(screen.getByRole("button", { name: "Load JSON into builder" }));
    expect(change).not.toHaveBeenCalled();
    expect((screen.getByLabelText("Root group operator") as HTMLSelectElement).value).toBe("any");
    fireEvent.change(screen.getByLabelText("Filter name"), { target: { value: "Pilot" } });
    fireEvent.click(screen.getByRole("button", { name: "Save filter" }));
    expect(localStorage.getItem("looninspect.device-scopes.org.operator")).toContain("Pilot");
    fireEvent.change(screen.getByLabelText("Import scope JSON"), { target: { value: '{"rules":[{"field":"script"}]}' } });
    fireEvent.click(screen.getByRole("button", { name: "Load JSON into builder" }));
    expect(screen.getByRole("alert").textContent).toContain("not a valid device filter");
    expect((screen.getByLabelText("Root group operator") as HTMLSelectElement).value).toBe("any");
  });
  it("shows an AI proposal, then requires load and apply separately", async () => {
    const change = setup();
    await screen.findByText(/42 current Jamf Macs/);
    fireEvent.click(screen.getByText("Propose a group with AI"));
    const draft = { match: "all", rules: [newRule()] };
    const previous = request.getMockImplementation()!;
    request.mockImplementation((path, options) => path.endsWith("propose-scope") ? Promise.resolve({ outcome: "proposed", scope: draft, detail: "Review proposed scope", matchedDevices: 12, warnings: [], provider: "ollama", model: "Qwen" }) : previous(path, options));
    fireEvent.change(screen.getByLabelText("Describe the proposed device group"), { target: { value: "Managed Macs" } });
    fireEvent.click(screen.getByRole("button", { name: "Propose a group" }));
    const result = await screen.findByLabelText("AI group proposal");
    expect(within(result).getByText(/12 Macs matched/)).toBeTruthy();
    expect(change).not.toHaveBeenCalled();
    fireEvent.click(within(result).getByRole("button", { name: "Load proposal into builder" }));
    expect(change).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "Apply device filter" }));
    expect(JSON.parse(change.mock.calls[0][0])).toEqual(draft);
    await waitFor(() => expect(request).toHaveBeenCalledWith("/application-patch-plans/propose-scope", expect.objectContaining({ method: "POST", json: expect.objectContaining({ question: "Managed Macs", provider: "ollama" }) })));
  });
});

it("reviews Managed conditions on mode changes without silently deleting them", async () => {
  const change = setup();
  await screen.findByText(/42 current Jamf Macs/);
  fireEvent.click(screen.getByRole("button", { name: "Add group" }));
  fireEvent.click(screen.getByRole("button", { name: "Smart group style" }));
  expect(screen.getByRole("alert").textContent).toContain("Remove Managed conditions");
  expect((screen.getByLabelText("Condition 1.1 field") as HTMLSelectElement).value).toBe("managed");
  expect((screen.getByRole("button", { name: "Apply device filter" }) as HTMLButtonElement).disabled).toBe(true);
  expect(change).not.toHaveBeenCalled();
  fireEvent.change(screen.getByLabelText("Condition 1.1 field"), { target: { value: "supervised" } });
  fireEvent.click(screen.getByRole("button", { name: "Apply device filter" }));
  expect(JSON.parse(change.mock.calls[0][0])).toEqual({ mode: "smart_group", match: "all", rules: [{ match: "any", rules: [newRule("supervised")] }] });
});

it("switches activity windows to date pickers and preserves only compatible values", async () => {
  setup();
  await screen.findByText(/42 current Jamf Macs/);
  fireEvent.click(screen.getByRole("button", { name: "Add condition" }));
  fireEvent.change(screen.getByLabelText("Condition 1 field"), { target: { value: "inventory" } });
  fireEvent.change(screen.getByLabelText("Condition 1 comparison"), { target: { value: "before" } });
  const value = screen.getByLabelText("Condition 1 value") as HTMLInputElement;
  expect(value.type).toBe("date"); expect(value.value).toBe("");
  fireEvent.change(value, { target: { value: "2024-02-29" } });
  fireEvent.change(screen.getByLabelText("Condition 1 comparison"), { target: { value: "after" } });
  expect(value.value).toBe("2024-02-29");
  fireEvent.change(screen.getByLabelText("Condition 1 comparison"), { target: { value: "older" } });
  expect(value.type).toBe("number"); expect(value.value).toBe("");
});
