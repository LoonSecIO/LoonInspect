// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { TenantSwitcher } from "./TenantSwitcher";
import { switchTenant } from "@/features/auth/api";
import * as drafts from "@/features/catalog/patchPlanDraft";
const state = vi.hoisted(() => ({ serverTenant: "tenant-a", current: { user: { id: "operator", tenants: [
  { id: "tenant-a", name: "Tenant A", current: true }, { id: "tenant-b", name: "Tenant B", current: false }
] } } }));
vi.mock("@/features/auth/store", () => ({ useAuthStore: (select: (s: typeof state.current) => unknown) => select(state.current) }));
vi.mock("@/features/auth/api", () => ({ switchTenant: vi.fn() }));
vi.mock("@/i18n/LocaleContext", () => ({ useLocale: () => ({ t: { common: { actingTenant: "Organization", switchTenantFailed: "Could not switch" } } }) }));
const key = "looninspect.patch-review.tenant-a.operator.synthetic";
const note = { revision: 1, values: { owner: "Unsaved", window: "", pilot: "", recovery: "", exceptions: "", approval: "" } };
const restoreWarnings: (() => void)[] = [];
const confirm = vi.fn<Window["confirm"]>();
let canceled = false;
let assign: ReturnType<typeof vi.fn>;
beforeEach(() => {
  state.serverTenant = "tenant-a";
  canceled = false;
  drafts.rememberReviewDraft(key, note);
  const suspend = drafts.suspendReviewDraftUnloadWarning;
  vi.spyOn(drafts, "suspendReviewDraftUnloadWarning").mockImplementation(() => {
    const restore = suspend(); restoreWarnings.push(restore); return restore;
  });
  vi.mocked(switchTenant).mockImplementation(async id => { state.serverTenant = id; return {} as Awaited<ReturnType<typeof switchTenant>>; });
  confirm.mockReturnValue(true);
  vi.spyOn(window, "confirm").mockImplementation(confirm);
  const realWindow = window;
  assign = vi.fn(() => {
    const event = new Event("beforeunload", { cancelable: true });
    realWindow.dispatchEvent(event);
    canceled = event.defaultPrevented;
  });
  vi.stubGlobal("window", new Proxy(realWindow, { get(target, property) {
    if (property === "location") return { assign };
    const value = Reflect.get(target, property, target);
    return typeof value === "function" ? value.bind(target) : value;
  } }));
});
afterEach(() => {
  cleanup(); vi.unstubAllGlobals(); restoreWarnings.splice(0).forEach(restore => restore());
  drafts.forgetReviewDraft(key); vi.restoreAllMocks(); vi.clearAllMocks();
});
it("cancels before changing the tenant session and preserves its draft", () => {
  confirm.mockReturnValue(false);
  render(<TenantSwitcher />);
  fireEvent.change(screen.getByLabelText("Organization"), { target: { value: "tenant-b" } });
  expect(switchTenant).not.toHaveBeenCalled(); expect(assign).not.toHaveBeenCalled();
  expect(state.serverTenant).toBe("tenant-a"); expect(drafts.readReviewDraft(key)).toEqual(note);
});
it("confirms before the session changes and cannot cancel the subsequent reload with its draft warning", async () => {
  render(<TenantSwitcher />);
  fireEvent.change(screen.getByLabelText("Organization"), { target: { value: "tenant-b" } });
  await waitFor(() => expect(assign).toHaveBeenCalledWith("/"));
  expect(confirm.mock.invocationCallOrder[0]).toBeLessThan(vi.mocked(switchTenant).mock.invocationCallOrder[0]);
  expect(state.serverTenant).toBe("tenant-b"); expect(canceled).toBe(false);
  expect(drafts.readReviewDraft(key)).toEqual(note);
});
it("keeps the draft warning during and after a failed tenant switch", async () => {
  let reject!: (error: Error) => void;
  vi.mocked(switchTenant).mockReturnValue(new Promise((_, fail) => { reject = fail; }));
  render(<TenantSwitcher />);
  fireEvent.change(screen.getByLabelText("Organization"), { target: { value: "tenant-b" } });
  const during = new Event("beforeunload", { cancelable: true }); window.dispatchEvent(during);
  expect(during.defaultPrevented).toBe(true);
  reject(new Error("Synthetic failure"));
  await screen.findByTitle("Could not switch");
  const after = new Event("beforeunload", { cancelable: true }); window.dispatchEvent(after);
  expect(after.defaultPrevented).toBe(true);
  expect(state.serverTenant).toBe("tenant-a"); expect(assign).not.toHaveBeenCalled();
  expect(drafts.readReviewDraft(key)).toEqual(note);
});
