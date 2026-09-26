/** Settings › Accounts (#653): the two-step sign-in policy, and removing another account's second factor. */

import { afterEach, describe, expect, it, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { ApiError, apiRequest } from "@/config/api";
import { removeSecondFactor } from "@/features/accounts/api";
import { MfaPolicyView, type PolicyRead } from "@/features/accounts/MfaPolicyControl";
import { savePolicy } from "@/features/accounts/mfaPolicy";
import { sentence } from "@/features/accounts/twoStep";
import { enrolmentRedirect, MY_ACCOUNT, useAuthStore } from "@/features/auth/store";
import type { AuthUser } from "@/features/auth/types";
import { getMfaPolicy } from "@/features/settings/api";
import type { MfaPolicy } from "@/features/settings/types";
import { en } from "@/i18n/en";

vi.mock("@/config/api", async (importOriginal) => ({ ...(await importOriginal<typeof import("@/config/api")>()), apiRequest: vi.fn() }));
afterEach(() => vi.clearAllMocks());

const words = en.accounts.mfaPolicy;
const view = (read: PolicyRead, canWrite: boolean, pending: MfaPolicy | null = null) =>
  renderToStaticMarkup(<MfaPolicyView read={read} canWrite={canWrite} pending={pending} copy={en.accounts} />);

describe("the two-step sign-in policy on Accounts (#653)", () => {
  it("is read; a reader sees the word in force and nothing to press; an administrator is asked before a change", async () => {
    await getMfaPolicy();
    expect(apiRequest).toHaveBeenCalledWith("/settings/mfa-policy");
    const reader = view({ state: "ready", policy: "admins" }, false);
    expect(reader).toContain('<p class="text-sm font-medium">Administrators</p>');
    expect(reader).not.toContain("<button");
    expect(view({ state: "failed" }, true)).toContain(words.unreadable); // unknown, never "off"
    const writer = view({ state: "ready", policy: "off" }, true);
    for (const name of ["Off", "Administrators", "Everyone"]) expect(writer).toContain(`>${name}</button>`);
    expect(writer).toMatch(/aria-pressed="true"[^>]*>Off</);
    expect(view({ state: "ready", policy: "off" }, true, "everyone")).toContain(words.confirm.everyone);
    expect(words.confirm.admins).toContain("next request, every administrator without two-step sign-in, yourself included,");
  });

  it("writes the word, then reads the account again, so a setter it now holds is routed to My Account", async () => {
    const admin = { id: "a1", roles: ["admin"], permissions: [], tenants: [], mfaEnrolmentRequired: false } as unknown as AuthUser;
    useAuthStore.setState({ status: "authenticated", user: admin });
    vi.mocked(apiRequest).mockResolvedValueOnce({ mfaRequired: "admins" }).mockResolvedValueOnce({ ...admin, mfaEnrolmentRequired: true });
    expect(await savePolicy("admins", "fallback")).toEqual({ policy: "admins" });
    expect(apiRequest).toHaveBeenNthCalledWith(1, "/settings/mfa-policy", { method: "PUT", json: { mfaRequired: "admins" } });
    expect(enrolmentRedirect(useAuthStore.getState().user, "/settings/accounts")).toBe(MY_ACCOUNT);
    vi.mocked(apiRequest).mockRejectedValueOnce(new ApiError(403, "Insufficient permissions"));
    expect(await savePolicy("everyone", "fallback")).toEqual({ error: "Insufficient permissions" });
  });
});

describe("removing another account's second factor (#653)", () => {
  it("names the consequence first, deletes, and shows a refusal in the server's words", async () => {
    expect(en.accounts.removeFactorConfirm("bo@example.com")).toContain("bo@example.com? Every session of that account is signed out");
    await removeSecondFactor("b 2");
    expect(apiRequest).toHaveBeenCalledWith("/accounts/b%202/mfa", { method: "DELETE" });
    const own = "You cannot remove your own second factor here. Ask another administrator to remove it.";
    vi.mocked(apiRequest).mockRejectedValueOnce(new ApiError(409, own));
    expect(sentence(await removeSecondFactor("a1").catch((caught: unknown) => caught), "fallback")).toBe(own);
  });
});
