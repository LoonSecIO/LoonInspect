// @vitest-environment jsdom
/** The once-only notice that the update check now asks LoonSec (#819): who is shown it, in which words, and what
 *  Dismiss does when it lands and when it does not. The API module and the permissions are stubbed; nothing is fetched. */

import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError } from "@/config/api";
import { PERMISSIONS } from "@/features/auth/types";
import type { UpdateStatusResponse } from "@/features/system/api";
import { UpdateCheckNotice } from "@/features/system/UpdateCheckNotice";
import { en } from "@/i18n/en";

vi.mock("@/i18n/LocaleContext", async () => {
  const { en: t } = await import("@/i18n/en");
  return { useLocale: () => ({ t, locale: "en" }) };
});
const api = vi.hoisted(() => ({ getUpdateStatus: vi.fn(), dismissUpdateNotice: vi.fn() }));
vi.mock("@/features/system/api", () => api);
const held = vi.hoisted(() => ({ permissions: [] as string[] }));
vi.mock("@/features/auth/store", () => ({ useHasPermission: (permission: string) => held.permissions.includes(permission) }));

const words = en.updateCheckNotice;
const ADMIN = [PERMISSIONS.SYSTEM_READ, PERMISSIONS.SYSTEM_WRITE];
// An instance that held an account when it was updated to v1.2.0: the notice pending, its first check of LoonSec's
// update service owed. As the route's JSON carries it.
const PENDING: UpdateStatusResponse = JSON.parse(`{"enabled": true, "currentVersion": "2026.11.19+0123abc",
  "updateAvailable": null, "latestSha": null, "checkedAt": null, "latestTag": null, "releaseUrl": null, "reason": "not_checked",
  "provider": "loonsec", "providerHost": "api.next.loonsec.io", "kind": "container", "lastBody": null,
  "nextBody": {"contract": "v1", "release": "v1.2.0", "kind": "container", "stage": "collecting"},
  "nextCheckAt": "2026-11-20T07:41:00Z", "noticePending": true}`);

async function open(status: UpdateStatusResponse, permissions: string[] = ADMIN) {
  held.permissions = permissions;
  api.getUpdateStatus.mockResolvedValue(status);
  await act(async () => {
    render(
      <MemoryRouter>
        <UpdateCheckNotice />
      </MemoryRouter>
    );
  });
}
const notice = () => screen.queryByRole("region", { name: words.label });
const dismiss = () =>
  act(async () => {
    fireEvent.click(screen.getByRole("button", { name: words.dismiss }));
  });

beforeEach(() => {
  api.getUpdateStatus.mockReset();
  api.dismissUpdateNotice.mockReset();
});
afterEach(cleanup);

describe("the notice that the update check now asks LoonSec", () => {
  it("is shown to an administrator while it is pending and the check asks LoonSec's service, with the container's switch", async () => {
    await open(PENDING);

    const text = notice()?.textContent ?? "";
    expect(text).toContain(words.asks);
    expect(text).toContain(`${words.updates}${words.shows.container}`);
    expect(text).toContain("UPDATE_CHECK=false in .env");
    expect(text).not.toContain("Check for Updates Daily");
    expect(screen.getByRole("link", { name: words.updates }).getAttribute("href")).toBe("/settings/support#updates");
  });

  it("is not shown to a reader, who is not asked for it", async () => {
    await open(PENDING, [PERMISSIONS.SYSTEM_READ]);

    expect(notice()).toBeNull();
    expect(api.getUpdateStatus).not.toHaveBeenCalled();
  });

  it.each([
    ["once dismissed", { noticePending: false }],
    ["while UPDATE_CHECK_URL names a GitHub-shaped address", { provider: "github", providerHost: "api.github.com", nextBody: null }],
    ["while the check is off", { enabled: false, reason: "disabled", nextBody: null, nextCheckAt: null }],
    ["on a build that asks nothing", { reason: "dev_build", nextBody: null, nextCheckAt: null }]
  ] as const)("is not shown %s", async (_, change) => {
    await open({ ...PENDING, ...change });

    expect(api.getUpdateStatus).toHaveBeenCalledTimes(1);
    expect(notice()).toBeNull();
  });

  it("in LoonInspect.app, names its menu item and no .env", async () => {
    await open({ ...PENDING, kind: "mac-app" });

    const text = notice()?.textContent ?? "";
    expect(text).toContain(`${words.updates}${words.shows["mac-app"]}`);
    expect(text).toContain("LoonInspect › Check for Updates Daily");
    expect(text).not.toMatch(/\.env|UPDATE_CHECK|docker/);
  });

  it("goes for good once Dismiss lands, after one call of the route", async () => {
    await open(PENDING);
    api.dismissUpdateNotice.mockResolvedValue({ ...PENDING, noticePending: false });

    await dismiss();

    expect(api.dismissUpdateNotice).toHaveBeenCalledTimes(1);
    expect(notice()).toBeNull();
  });

  it.each([
    ["refused, the permission withdrawn", new ApiError(403, "Insufficient permissions"), words.refused],
    ["unanswered, the instance unreachable", new TypeError("Failed to fetch"), words.unreachable],
    ["answered with an error", new ApiError(500, null), words.failed(500)]
  ])("stays up when the dismissal is %s, and says why", async (_, error, said) => {
    await open(PENDING);
    api.dismissUpdateNotice.mockRejectedValue(error);

    await dismiss();

    expect(api.dismissUpdateNotice).toHaveBeenCalledTimes(1);
    expect(notice()?.textContent).toContain(words.asks);
    expect(screen.getByRole("alert").textContent).toBe(said);
    expect(screen.getByRole("button", { name: words.dismiss }).hasAttribute("disabled")).toBe(false);
  });
});
