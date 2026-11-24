// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { logout as logoutRequest } from "@/features/auth/api";
import type { AuthUser } from "@/features/auth/types";
import { confirmReviewDraftSessionChange, forgetReviewDraft, readReviewDraft, rememberReviewDraft } from "@/features/catalog/patchPlanDraft";
import { useAuthStore } from "./store";

const handlers = vi.hoisted(() => ({ unauthorized: null as (() => void) | null }));
vi.mock("@/config/api", () => ({ setUnauthorizedHandler: (handler: (() => void) | null) => { handlers.unauthorized = handler; } }));
vi.mock("@/features/auth/api", () => ({ logout: vi.fn() }));

const draftKey = "looninspect.patch-review.tenant-a.operator-a.synthetic-plan";
const note = { revision: 1, values: { owner: "Synthetic owner", window: "", pilot: "", recovery: "", exceptions: "", approval: "CHG-1" } };
const unrelatedKey = "looninspect.update-banner-dismissed";
function unloadPrevented() {
  const event = new Event("beforeunload", { cancelable: true }); window.dispatchEvent(event); return event.defaultPrevented;
}
beforeEach(() => {
  vi.mocked(logoutRequest).mockResolvedValue(undefined);
  useAuthStore.setState({ status: "authenticated", user: { id: "operator-a" } as AuthUser });
});
afterEach(() => { vi.restoreAllMocks(); forgetReviewDraft(draftKey); sessionStorage.clear(); });

it("sign-out removes this account's unsaved review notes and disarms their prompts for the next user", async () => {
  rememberReviewDraft(draftKey, note);
  sessionStorage.setItem(unrelatedKey, "true");
  const confirm = vi.spyOn(window, "confirm").mockReturnValue(false);
  await useAuthStore.getState().logout();
  expect(sessionStorage.getItem(draftKey)).toBeNull();
  expect(readReviewDraft(draftKey)).toBeNull();
  expect(confirmReviewDraftSessionChange()).toBe(true);
  expect(confirm).not.toHaveBeenCalled();
  expect(unloadPrevented()).toBe(false);
  expect(sessionStorage.getItem(unrelatedKey)).toBe("true");
});

it("sign-out clears memory-only notes too, even when the sign-out request fails", async () => {
  vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => { throw new Error("Storage unavailable"); });
  expect(rememberReviewDraft(draftKey, note)).toBe(false);
  vi.mocked(logoutRequest).mockRejectedValue(new Error("Synthetic network failure"));
  await expect(useAuthStore.getState().logout()).rejects.toThrow("Synthetic network failure");
  expect(useAuthStore.getState().user).toBeNull();
  expect(readReviewDraft(draftKey)).toBeNull();
  expect(confirmReviewDraftSessionChange()).toBe(true);
  expect(unloadPrevented()).toBe(false);
});

it("an expired session (401) keeps the draft and its warning for the returning user", () => {
  rememberReviewDraft(draftKey, note);
  handlers.unauthorized?.();
  expect(useAuthStore.getState().user).toBeNull();
  expect(readReviewDraft(draftKey)).toEqual(note);
  expect(unloadPrevented()).toBe(true);
});
