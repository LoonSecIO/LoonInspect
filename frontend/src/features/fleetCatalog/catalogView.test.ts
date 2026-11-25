import { describe, expect, it } from "vitest";
import {
  checkFailed,
  emptyState,
  historyStatusOf,
  movedAt,
  scopedCount,
  sortTitles,
  statusOf,
  titleMatches
} from "@/features/fleetCatalog/catalogView";
import type { FleetCatalog, FleetCatalogState, FleetCatalogTitle } from "@/features/fleetCatalog/types";

function title(overrides: Partial<FleetCatalogTitle> = {}): FleetCatalogTitle {
  return {
    slug: "alpha",
    name: "Alpha",
    bundleId: "com.example.alpha",
    latestVersion: "2.0",
    previousVersion: null,
    versionChangedAt: null,
    firstSeenAt: "2026-11-15T12:00:00Z",
    deviceCount: 3,
    devicesBehind: 1,
    devicesCurrent: 2,
    inCatalogSince: null,
    versionBefore: null,
    historyReadAt: null,
    ...overrides
  };
}

function state(overrides: Partial<FleetCatalogState> = {}): FleetCatalogState {
  return {
    checkedAt: "2026-11-15T12:00:00Z",
    changedAt: "2026-11-15T12:00:00Z",
    outcome: "ok",
    detail: null,
    appCount: 500,
    historyCheckedAt: null,
    historyOutcome: null,
    historyDetail: null,
    ...overrides
  };
}

function catalog(overrides: Partial<FleetCatalog> = {}): FleetCatalog {
  return {
    enabled: true,
    source: "fleetdm/fleet",
    state: state(),
    items: [title()],
    total: 1,
    page: 1,
    pageSize: 5000,
    installedTitlesWithHistory: 0,
    installedTitles: 1,
    ...overrides
  };
}

describe("statusOf", () => {
  it("tells no check yet from a check that answered from one that did not", () => {
    expect(statusOf(null)).toBe("never");
    expect(statusOf(state({ checkedAt: null, outcome: null }))).toBe("never");
    expect(statusOf(state({ outcome: "ok" }))).toBe("answered");
    // GitHub answering that nothing moved is an answer, not a failure and not a silence.
    expect(statusOf(state({ outcome: "unchanged" }))).toBe("answered");
    for (const outcome of ["refused", "unreachable", "unexpected"] as const) {
      expect(statusOf(state({ outcome }))).toBe("failed");
      expect(checkFailed(state({ outcome }))).toBe(true);
    }
    expect(checkFailed(null)).toBe(false);
  });
});

describe("emptyState", () => {
  const showing = { searching: false, installedOnly: true };

  it("is null while there are rows to show", () => {
    const held = catalog();
    expect(emptyState(held, held.items, showing)).toBeNull();
  });

  it("says the flag is off before anything else", () => {
    expect(emptyState(catalog({ enabled: false, state: null, items: [] }), [], showing)).toBe("flagOff");
  });

  it("says GitHub has never been asked, which is not an empty catalog", () => {
    expect(emptyState(catalog({ state: null, items: [] }), [], showing)).toBe("neverChecked");
  });

  it("says nothing has been read yet when every check so far failed", () => {
    const failed = catalog({ state: state({ outcome: "refused", appCount: 0, changedAt: null }), items: [] });
    expect(emptyState(failed, [], showing)).toBe("neverRead");
  });

  it("says Fleet lists nothing installed here, when the catalog was read and no Mac has a title", () => {
    expect(emptyState(catalog({ items: [], installedTitles: 0 }), [], showing)).toBe("noneInstalled");
    // A search over nothing is still nothing installed, not a search that missed.
    expect(emptyState(catalog({ items: [], installedTitles: 0 }), [], { searching: true, installedOnly: true })).toBe(
      "noneInstalled"
    );
  });

  it("tells a search that missed among installed titles from one that missed in the whole catalog", () => {
    const held = catalog();
    expect(emptyState(held, [], { searching: true, installedOnly: true })).toBe("noMatchInstalled");
    expect(emptyState(held, [], { searching: true, installedOnly: false })).toBe("noMatch");
  });

  it("keeps showing titles read earlier when the last check failed", () => {
    const stale = catalog({ state: state({ outcome: "unreachable", detail: "No answer from api.github.com." }) });
    expect(emptyState(stale, stale.items, showing)).toBeNull();
  });
});

describe("titleMatches", () => {
  it("matches the name, the bundle ID, the slug and the version, whatever the case", () => {
    const alpha = title();
    expect(titleMatches(alpha, "")).toBe(true);
    expect(titleMatches(alpha, "  ")).toBe(true);
    expect(titleMatches(alpha, "ALPH")).toBe(true);
    expect(titleMatches(alpha, "com.example")).toBe(true);
    expect(titleMatches(alpha, "2.0")).toBe(true);
    expect(titleMatches(alpha, "beta")).toBe(false);
  });
});

describe("sortTitles", () => {
  const alpha = title({ slug: "alpha", name: "alpha", deviceCount: 3, devicesBehind: 1, latestVersion: "2.0" });
  const beta = title({
    slug: "beta",
    name: "Beta",
    deviceCount: 10,
    devicesBehind: 0,
    latestVersion: "10.1",
    versionChangedAt: "2026-11-14T09:00:00Z",
    previousVersion: "10.0"
  });
  const gamma = title({
    slug: "gamma",
    name: "Gamma",
    deviceCount: 1,
    devicesBehind: 1,
    latestVersion: "9.9",
    versionChangedAt: "2026-11-10T09:00:00Z",
    previousVersion: "9.8"
  });
  const slugs = (titles: FleetCatalogTitle[]) => titles.map((item) => item.slug);

  it("sorts names without regard to case and leaves its input alone", () => {
    const input = [gamma, beta, alpha];
    expect(slugs(sortTitles(input, "name", "asc"))).toEqual(["alpha", "beta", "gamma"]);
    expect(slugs(input)).toEqual(["gamma", "beta", "alpha"]);
  });

  it("sorts counts as numbers and versions by their numbers", () => {
    expect(slugs(sortTitles([alpha, beta, gamma], "deviceCount", "desc"))).toEqual(["beta", "alpha", "gamma"]);
    // 9.9 before 10.1: a plain string sort would put 10.1 first.
    expect(slugs(sortTitles([alpha, beta, gamma], "latestVersion", "asc"))).toEqual(["alpha", "gamma", "beta"]);
  });

  it("breaks a tie by name", () => {
    expect(slugs(sortTitles([gamma, alpha], "devicesBehind", "asc"))).toEqual(["alpha", "gamma"]);
  });

  it("puts a title whose version has not moved last, in both directions", () => {
    expect(slugs(sortTitles([alpha, beta, gamma], "versionChangedAt", "desc"))).toEqual(["beta", "gamma", "alpha"]);
    expect(slugs(sortTitles([alpha, beta, gamma], "versionChangedAt", "asc"))).toEqual(["gamma", "beta", "alpha"]);
  });

  it("sorts by the history's date where there is one, which can be older than any move seen here (#838)", () => {
    const dated = { ...alpha, inCatalogSince: "2026-09-01T09:00:00Z", historyReadAt: "2026-11-15T12:00:00Z" };
    expect(slugs(sortTitles([dated, beta, gamma], "versionChangedAt", "asc"))).toEqual(["alpha", "gamma", "beta"]);
  });

  it("sorts by the device filter's counts, a title they do not hold yet last in both directions (#905)", () => {
    const counts = { alpha: 2, gamma: 5 }; // Fleet listed beta after these were read.
    expect(slugs(sortTitles([alpha, beta, gamma], "scopedCount", "desc", counts))).toEqual(["gamma", "alpha", "beta"]);
    expect(slugs(sortTitles([beta, gamma, alpha], "scopedCount", "asc", counts))).toEqual(["alpha", "gamma", "beta"]);
    expect(scopedCount(counts, "toString")).toBeNull(); // own keys only
  });
});

describe("the version history (#838)", () => {
  it("dates the latest version by the history first, then by a move seen here, else not at all", () => {
    expect(movedAt(title({ inCatalogSince: "2026-09-01T09:00:00Z", versionChangedAt: "2026-11-14T09:00:00Z" }))).toBe(
      "2026-09-01T09:00:00Z"
    );
    expect(movedAt(title({ versionChangedAt: "2026-11-14T09:00:00Z" }))).toBe("2026-11-14T09:00:00Z");
    expect(movedAt(title())).toBeNull();
  });

  it("tells no read yet, a read, holding back for GitHub's hour, and a failure apart", () => {
    const at = "2026-11-21T12:00:00Z";
    expect(historyStatusOf(null)).toBe("none");
    expect(historyStatusOf(state())).toBe("none");
    expect(historyStatusOf(state({ historyCheckedAt: at, historyOutcome: "ok" }))).toBe("ok");
    expect(historyStatusOf(state({ historyCheckedAt: at, historyOutcome: "waiting" }))).toBe("waiting");
    for (const outcome of ["refused", "unreachable", "unexpected"] as const) {
      expect(historyStatusOf(state({ historyCheckedAt: at, historyOutcome: outcome }))).toBe("failed");
    }
  });
});
