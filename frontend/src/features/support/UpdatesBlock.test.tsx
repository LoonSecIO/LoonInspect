// @vitest-environment jsdom
/** Settings › Support › Updates once its read lands (#819): what the last check sent, the answer, and what the next would
 *  send, for statuses as the wire carries them; `updateStatus.test.ts` holds the decisions. Nothing is fetched. */

import { act, cleanup, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { UpdatesBlock } from "@/features/support/UpdatesBlock";
import type { UpdateStatusResponse } from "@/features/system/api";
import { en } from "@/i18n/en";

vi.mock("@/i18n/LocaleContext", async () => {
  const { en: t } = await import("@/i18n/en");
  return { useLocale: () => ({ t, locale: "en" }) };
});
const api = vi.hoisted(() => ({ getUpdateStatus: vi.fn() }));
vi.mock("@/features/system/api", () => api);

const words = en.support.updates;
const PAGE = "https://github.com/LoonSecIO/LoonInspect/releases/tag/v1.2.1";
// The route's answer after a check like the one backend/tests/test_update_status_route_db.py drives: made on day
// 20776 by an instance last answered on day 20775, and answered with v1.2.1. Its bodies' keys in the order sent.
const WIRE = `{"enabled": true, "currentVersion": "2026.11.19+0123abc", "updateAvailable": true, "latestSha": null,
  "checkedAt": "2026-11-19T10:00:00Z", "latestTag": "v1.2.1", "releaseUrl": "${PAGE}", "reason": null,
  "provider": "loonsec", "providerHost": "api.next.loonsec.io", "kind": "container",
  "lastBody": {"contract": "v1", "release": "v1.2.0", "kind": "container", "stage": "collecting", "last": 20775},
  "nextBody": {"contract": "v1", "release": "v1.2.0", "kind": "container", "stage": "collecting", "last": 20776},
  "nextCheckAt": "2026-11-20T07:41:00Z", "noticePending": false}`;
const AFTER: UpdateStatusResponse = JSON.parse(WIRE);

async function open(status: UpdateStatusResponse) {
  api.getUpdateStatus.mockResolvedValue(status);
  await act(async () => {
    render(<UpdatesBlock />);
  });
}
/** The JSON text a slot prints, or null when it prints why it has none. */
const printed = (label: string) => screen.getByText(label).closest("figure")?.querySelector("pre")?.textContent ?? null;
const keys = (label: string) => Object.keys(JSON.parse(printed(label) ?? "{}"));

beforeEach(() => {
  vi.spyOn(Date, "now").mockReturnValue(Date.parse("2026-11-19T10:00:30Z"));
  api.getUpdateStatus.mockReset();
});
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe("the Updates block says what the check sends", () => {
  it("shows the body the last check sent, as sent, the answer to it, and the next body carrying the day given", async () => {
    await open(AFTER);

    expect(printed(words.sends.lastSent)).toBe(JSON.stringify(JSON.parse(WIRE).lastBody, null, 2));
    expect(keys(words.sends.lastSent)).toEqual(["contract", "release", "kind", "stage", "last"]);
    expect(screen.getByText(words.available("v1.2.1"))).toBeTruthy();
    expect(screen.getByRole("link", { name: /v1\.2\.1/ }).getAttribute("href")).toBe(PAGE);
    expect(printed(words.sends.nextSends)).toContain('"last": 20776');
    expect(screen.getByText("api.next.loonsec.io")).toBeTruthy();
    expect(screen.getByText(words.sends.shape.loonsec)).toBeTruthy();
    expect(screen.queryByText(words.sends.owedNow)).toBeNull();
  });

  it("before the first answer, says nothing was sent and shows a next body with no last", async () => {
    const nextBody = { contract: "v1", release: "v1.2.0", kind: "container", stage: "unclaimed" };
    await open({ ...AFTER, updateAvailable: null, reason: "not_checked", checkedAt: null, lastBody: null, nextBody });

    expect(printed(words.sends.lastSent)).toBeNull();
    expect(screen.getByText(words.sends.none.not_sent)).toBeTruthy();
    expect(keys(words.sends.nextSends)).toEqual(["contract", "release", "kind", "stage"]);
  });

  it("asking a GitHub-shaped address, shows no body on either side and says why", async () => {
    await open({ ...AFTER, provider: "github", providerHost: "api.github.com", lastBody: null, nextBody: null });

    expect([printed(words.sends.lastSent), printed(words.sends.nextSends)]).toEqual([null, null]);
    expect(screen.getAllByText(words.sends.none.github)).toHaveLength(2);
    expect(screen.getByText(words.sends.shape.github)).toBeTruthy();
  });

  it("with the check off, still shows what the last check sent, and that nothing is sent next", async () => {
    await open({ ...AFTER, reason: "disabled", updateAvailable: null, checkedAt: null, nextBody: null, nextCheckAt: null });

    expect(keys(words.sends.lastSent)).toEqual(["contract", "release", "kind", "stage", "last"]);
    expect(printed(words.sends.nextSends)).toBeNull();
    expect(screen.getAllByText(words.sends.none.off)).toHaveLength(2); // the next body, and the next check
  });
});
