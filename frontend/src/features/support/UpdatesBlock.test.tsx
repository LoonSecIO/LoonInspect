// @vitest-environment jsdom
/** Settings › Support › Updates once its read lands (#819): what the last check sent, the answer, and what the next would
 *  send, for statuses as the wire carries them; `updateStatus.test.ts` holds the decisions. Then how the instance is
 *  updated (#820): LoonInspect.app's steps and words from a `mac-app` read, the container's from any other. Nothing is fetched. */

import { act, cleanup, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { UpdatesBlock } from "@/features/support/UpdatesBlock";
import { SUPPORT_LINKS } from "@/features/support/links";
import { UPDATE_REASONS, type UpdateStatusResponse } from "@/features/system/api";
import { upgradeCommands } from "@/features/system/updateStatus";
import { en } from "@/i18n/en";

vi.mock("@/i18n/LocaleContext", async () => {
  const { en: t } = await import("@/i18n/en");
  return { useLocale: () => ({ t, locale: "en" }) };
});
const api = vi.hoisted(() => ({ getUpdateStatus: vi.fn() }));
vi.mock("@/features/system/api", async (actual) => ({ ...(await actual<object>()), ...api }));

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

// LoonInspect.app's answer (#820): the same check, sent with kind mac-app.
const APP: UpdateStatusResponse = { ...AFTER, kind: "mac-app", lastBody: { ...AFTER.lastBody, kind: "mac-app" },
  nextBody: { ...AFTER.nextBody, kind: "mac-app" } };
const CONTAINERS = /docker|compose|\.env|container/i;
const drawn = () => document.body.textContent ?? "";
const linked = (name: string) => screen.getByRole("link", { name: new RegExp(name) }).getAttribute("href");

describe("from LoonInspect.app, the block says how the app is updated (#820)", () => {
  it("with an update available, prints the app's steps and links the release's page, and nothing of the container's", async () => {
    await open(APP);

    expect([...document.querySelectorAll("ol > li")].map((step) => step.textContent)).toEqual(words.app.steps);
    expect(linked(words.app.releasePage)).toBe(PAGE);
    expect(linked(words.app.rollbackLink)).toBe(SUPPORT_LINKS.macAppUpdates);
    for (const sentence of [words.app.help, words.app.stepsIntro, words.app.selfHostedOnly]) expect(screen.getByText(sentence)).toBeTruthy();
    expect(drawn()).not.toMatch(CONTAINERS);
    expect(document.querySelectorAll("pre")).toHaveLength(2); // the two bodies, and no commands
  });

  const states: [string, Partial<UpdateStatusResponse>][] = [
    ...UPDATE_REASONS.map((reason): [string, Partial<UpdateStatusResponse>] => [reason, { updateAvailable: null, reason }]),
    ["a check owed now", { nextCheckAt: "2026-11-19T09:59:00Z" }],
    ["no moment drawn yet", { nextCheckAt: null }],
    ["no release page named", { releaseUrl: null }]
  ];
  it.each(states)("reads without docker, compose, .env or container: %s", async (_, over) => {
    await open({ ...APP, ...over });

    expect(drawn()).not.toMatch(CONTAINERS);
  });

  it("says the check is off by the menu item, or the app's environment, and that shell.log says which", async () => {
    await open({ ...APP, updateAvailable: null, reason: "disabled", nextBody: null, nextCheckAt: null });

    expect(screen.getByText(words.app.reasons.disabled)).toBeTruthy();
    expect(words.app.reasons.disabled).toMatch(/LoonInspect › Check for Updates Daily .*the app's environment.*shell\.log/);
  });

  it("with no release page named, links the list of releases", async () => {
    await open({ ...APP, releaseUrl: null });

    expect(linked(words.releasesPage)).toBe(SUPPORT_LINKS.releases);
  });
});

describe("from a container, the block reads as it did before (#820)", () => {
  it("prints the compose steps, dump first, and the container's rollback, and none of the app's words", async () => {
    await open(AFTER);

    expect([...document.querySelectorAll("pre")].at(-1)?.textContent).toBe(upgradeCommands("v1.2.1").join("\n"));
    for (const sentence of [words.help, words.stepsHeading, words.stepsIntro, words.selfHostedOnly]) expect(screen.getByText(sentence)).toBeTruthy();
    expect(linked(words.rollbackLink)).toBe(SUPPORT_LINKS.rollbackDocs);
    expect(document.querySelector("ol")).toBeNull();
    expect(drawn()).not.toContain(words.app.stepsHeading);
  });

  it.each(UPDATE_REASONS)("says the container's own sentence for %s", async (reason) => {
    await open({ ...AFTER, updateAvailable: null, reason });

    expect(screen.getByText(words.reasons[reason])).toBeTruthy();
  });

  it("keeps the disabled sentence word for word", async () => {
    await open({ ...AFTER, updateAvailable: null, reason: "disabled", nextBody: null, nextCheckAt: null });

    expect(screen.getByText("Checking is off: UPDATE_CHECK=false is set for this container, so nothing is asked and no notice " +
      "appears. To turn it on, remove that line from the .env file beside docker-compose.yml and run docker compose up -d.")).toBeTruthy();
  });

  it("draws no steps before the read says which kind this is, nor after it fails", async () => {
    api.getUpdateStatus.mockRejectedValue(new Error("unreachable"));
    await act(async () => {
      render(<UpdatesBlock />);
    });

    expect(screen.getByText(words.errorLoading)).toBeTruthy();
    expect(screen.queryByText(words.stepsHeading) ?? screen.queryByText(words.app.stepsHeading)).toBeNull();
  });
});
