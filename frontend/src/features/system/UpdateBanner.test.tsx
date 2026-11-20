// @vitest-environment jsdom
/** The update banner once its read lands (#407, #820): from LoonInspect.app, the app's own steps and the release's page,
 *  where its disk image is; from a container, what changed and how to update, as before. Nothing at all while the check
 *  cannot answer. The API and the permission are stubbed; nothing is fetched. */

import { act, cleanup, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { SUPPORT_LINKS } from "@/features/support/links";
import type { UpdateStatusResponse } from "@/features/system/api";
import { UpdateBanner } from "@/features/system/UpdateBanner";
import { UPDATES_HREF } from "@/features/system/updateStatus";
import { en } from "@/i18n/en";

vi.mock("@/i18n/LocaleContext", async () => {
  const { en: t } = await import("@/i18n/en");
  return { useLocale: () => ({ t, locale: "en" }) };
});
const api = vi.hoisted(() => ({ getUpdateStatus: vi.fn() }));
vi.mock("@/features/system/api", () => api);
vi.mock("@/features/auth/store", () => ({ useHasPermission: () => true }));

const words = en.system;
const PAGE = "https://github.com/LoonSecIO/LoonInspect/releases/tag/v1.2.1";
const AVAILABLE = { updateAvailable: true, latestTag: "v1.2.1", releaseUrl: PAGE, reason: null, kind: "container" };

/** The banner's words as a reader sees them, or null when it draws nothing. */
async function banner(over: Partial<UpdateStatusResponse>): Promise<string | null> {
  api.getUpdateStatus.mockResolvedValue({ ...AVAILABLE, ...over });
  await act(async () => {
    render(
      <MemoryRouter>
        <UpdateBanner />
      </MemoryRouter>
    );
  });
  return screen.queryByRole("status")?.textContent ?? null;
}
const linked = (name: string) => screen.getByRole("link", { name: new RegExp(name) }).getAttribute("href");

beforeEach(() => {
  sessionStorage.clear();
  api.getUpdateStatus.mockReset();
});
afterEach(cleanup);

describe("the update banner", () => {
  it("from LoonInspect.app, prints the app's steps and links the release's page, and no docker, compose or .env", async () => {
    const text = await banner({ kind: "mac-app" });

    expect(text).toContain(words.updateAvailable("v1.2.1"));
    expect(text).toContain(words.updateAppSteps);
    expect(linked(words.updateAppRelease)).toBe(PAGE);
    expect(linked(words.updateHowTo)).toBe(UPDATES_HREF);
    expect(text).not.toMatch(/docker|compose|\.env|container/i);
  });

  it("from LoonInspect.app with no release page named, links the list of releases", async () => {
    await banner({ kind: "mac-app", releaseUrl: null });

    expect(linked(en.support.updates.releasesPage)).toBe(SUPPORT_LINKS.releases);
  });

  it("from a container, reads as before: what changed and how to update, word for word", async () => {
    expect(await banner({})).toBe("LoonInspect v1.2.1 is available—what changed (opens in a new tab)·how to update");
    expect(linked(words.updateWhatChanged)).toBe(PAGE);
    expect(linked(words.updateHowTo)).toBe(UPDATES_HREF);
  });

  it.each(["container", "mac-app"] as const)("from a %s, draws nothing while the check cannot answer", async (kind) => {
    expect(await banner({ kind, updateAvailable: null, reason: "disabled" })).toBeNull();
  });
});
