import { describe, expect, it } from "vitest";
import { UPDATE_REASONS, type UpdateStatusResponse } from "@/features/system/api";
import { de } from "@/i18n/de";
import { en } from "@/i18n/en";
import { bannerRelease, bodyText, describeSends, describeUpdate, shellSafeTag, TAG_PLACEHOLDER, UPDATES_HREF, upgradeCommands } from "./updateStatus";

function status(over: Partial<UpdateStatusResponse> = {}): UpdateStatusResponse {
  return {
    enabled: true,
    currentVersion: "2026.09.18+c41e044",
    updateAvailable: false,
    latestSha: "99361ed4b2c1a7f0e8d5c3b6a4917f2e0d8c5b3a",
    checkedAt: "2026-09-18T09:00:00Z",
    latestTag: "v2026.09.17",
    releaseUrl: "https://github.com/LoonSecIO/LoonInspect/releases/tag/v2026.09.17",
    reason: null,
    provider: "loonsec", providerHost: "api.next.loonsec.io", kind: "container", lastBody: null, nextBody: null,
    nextCheckAt: null, noticePending: false,
    ...over
  };
}

const REASONS = UPDATE_REASONS; // all seven, `not_checked` included

describe("describeUpdate", () => {
  it.each([
    [true, "available"],
    [false, "current"],
    [null, "unknown"]
  ] as const)("updateAvailable %s reads %s", (available, kind) => {
    expect(describeUpdate(status({ updateAvailable: available })).kind).toBe(kind);
  });

  it.each(REASONS)("an unknown carries its reason through: %s", (reason) => {
    expect(describeUpdate(status({ updateAvailable: null, reason, latestTag: null, releaseUrl: null }))).toEqual({
      kind: "unknown",
      reason,
      tag: null,
      releaseUrl: null
    });
  });

  it("an unknown commit still names the release it could not compare against", () => {
    const view = describeUpdate(status({ updateAvailable: null, reason: "unknown_commit" }));
    expect(view).toMatchObject({ kind: "unknown", reason: "unknown_commit", tag: "v2026.09.17" });
  });
});

describe("bannerRelease — true only", () => {
  it("names the release and its page when an update is available", () => {
    expect(bannerRelease(status({ updateAvailable: true }))).toEqual({
      tag: "v2026.09.17",
      releaseUrl: "https://github.com/LoonSecIO/LoonInspect/releases/tag/v2026.09.17"
    });
  });

  it.each(REASONS)("renders nothing while unknown, whatever the reason: %s", (reason) => {
    expect(bannerRelease(status({ updateAvailable: null, reason }))).toBeNull();
  });

  it("renders nothing when current", () => {
    expect(bannerRelease(status({ updateAvailable: false }))).toBeNull();
  });
});

describe("the upgrade steps", () => {
  it("dump first, then the release tag, then the stamped build, then the log", () => {
    const lines = upgradeCommands("v2026.09.17");
    expect(lines).toHaveLength(4);
    // Owner-only, and the umask scoped to the dump alone: a umask left in force would make
    // the checkout's files owner-only, and the image build copies those modes in.
    expect(lines[0]).toMatch(/^\(umask 077 && docker compose exec -T db pg_dump -U looninspect -d looninspect \| gzip > "looninspect-preupgrade-.*\.sql\.gz"\)$/);
    expect(lines[1]).toBe("git fetch --tags && git checkout v2026.09.17");
    expect(lines[2]).toBe("GIT_SHA=$(git rev-parse --short HEAD) docker compose up -d --build");
    expect(lines[3]).toBe("docker compose logs -f app");
    // The bare command that skipped the dump is gone for good.
    expect(lines.join("\n")).not.toContain("git pull");
  });

  it("uses a placeholder when no release is named", () => {
    expect(upgradeCommands(null)[1]).toBe(`git fetch --tags && git checkout ${TAG_PLACEHOLDER}`);
  });

  it.each(["v2026.09.17", "v2026.09.17.1", "v1.2.3-rc.1"])("interpolates a tag that is only a tag: %s", (tag) => {
    expect(shellSafeTag(tag)).toBe(tag);
  });

  it.each(["v1; rm -rf ~", "v1 && curl x", "$(id)", "`id`", "v1\nrm", "'v1'", "-v1", ""])(
    "never pastes a tag a shell would read as more than a tag: %j",
    (tag) => {
      expect(shellSafeTag(tag)).toBeNull();
      expect(upgradeCommands(tag)[1]).toBe(`git fetch --tags && git checkout ${TAG_PLACEHOLDER}`);
    }
  );

  it("the banner and the attention row both point at the block", () => {
    expect(UPDATES_HREF).toBe("/settings/support#updates");
  });
});

// After a check made on day 20776 by an instance last answered on day 20775 (`UpdatesBlock.test.tsx` renders it whole).
const BODY = { contract: "v1", release: "v1.2.0", kind: "container", stage: "collecting", last: 20775 };
const READ = Date.parse("2026-11-19T10:00:30Z");
const OFF = { reason: "disabled", updateAvailable: null, checkedAt: null, nextBody: null, nextCheckAt: null } as const;
const sends = (over: Partial<UpdateStatusResponse>) =>
  describeSends(status({ lastBody: BODY, nextBody: { ...BODY, last: 20776 }, nextCheckAt: "2026-11-20T07:41:00Z", ...over }), READ);

describe("what the check sends (#819)", () => {
  it("prints each body as JSON text with its keys in the order given, and when the next check is owed", () => {
    expect(sends({})).toEqual({
      provider: "loonsec",
      host: "api.next.loonsec.io",
      last: { json: '{\n  "contract": "v1",\n  "release": "v1.2.0",\n  "kind": "container",\n  "stage": "collecting",\n  "last": 20775\n}' },
      next: { json: bodyText({ ...BODY, last: 20776 }) },
      owed: { at: "2026-11-20T07:41:00Z", due: false }
    });
  });

  it.each([
    ["nothing sent yet", { lastBody: null, checkedAt: null }, "last", "not_sent"],
    ["the last check asked a GitHub-shaped address", { lastBody: null }, "last", "sent_none"],
    ["a GitHub-shaped address takes no body", { provider: "github", lastBody: null, nextBody: null }, "last", "github"],
    ["nor will it next", { provider: "github", lastBody: null, nextBody: null }, "next", "github"],
    ["the check off", OFF, "next", "off"],
    ["the check off, whatever the shape", { ...OFF, provider: "github" }, "next", "off"],
    ["the check off owes nothing", OFF, "owed", "off"],
    ["a development build", { ...OFF, reason: "dev_build" }, "next", "dev_build"],
    ["a development build owes nothing", { ...OFF, reason: "dev_build" }, "owed", "dev_build"],
    ["no row drawn yet", { nextCheckAt: null }, "owed", "not_drawn"]
  ] as const)("names why a slot is empty: %s", (_, over, slot, none) => {
    expect(sends(over)[slot]).toEqual({ none });
  });

  it("keeps the last body with the check off, owes a moment already past now, and names no unreadable host", () => {
    expect(sends(OFF).last).toEqual({ json: bodyText(BODY) });
    expect(sends({ nextCheckAt: "2026-11-19T09:59:00Z" }).owed).toEqual({ at: "2026-11-19T09:59:00Z", due: true });
    expect(sends({ providerHost: null }).host).toBeNull();
  });

  it("every reason and every empty slot has its sentence, in both languages", () => {
    for (const t of [en, de]) {
      for (const reason of UPDATE_REASONS) expect(t.support.updates.reasons[reason]).toMatch(/\S/);
      expect(Object.keys(t.support.updates.sends.none)).toEqual(["not_sent", "sent_none", "github", "off", "dev_build", "not_drawn"]);
      for (const sentence of Object.values(t.support.updates.sends.none)) expect(sentence).toMatch(/\S/);
    }
  });
});
