import { describe, expect, it } from "vitest";
import type { UpdateReason, UpdateStatusResponse } from "@/features/system/api";
import { bannerRelease, describeUpdate, shellSafeTag, TAG_PLACEHOLDER, UPDATES_HREF, upgradeCommands } from "./updateStatus";

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
    ...over
  };
}

const REASONS: UpdateReason[] = ["disabled", "dev_build", "unreachable", "refused", "no_release", "unknown_commit"];

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
