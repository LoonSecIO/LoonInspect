/**
 * Needs Attention (#106): the six predicates, the three collapses and the attestation
 * gate, executed rather than argued — the module #285 was aimed at first.
 *
 * Every scenario is plain data in, plain data out. The boundaries are the point: 59
 * minutes against 61, 47 hours against 49, `denied` against `error`, five rows against
 * six.
 */

import { describe, expect, it } from "vitest";
import type { Alert, AlertListResponse } from "@/features/alerts/types";
import type { Destination } from "@/features/destinations/types";
import type { CollectionSummary, MdmConnection } from "@/features/mdm/types";
import {
  MAX_ROWS,
  OVERDUE_GRACE_MS,
  composeAttention,
  isAllClear,
  type AttentionInputs,
  type Fetched
} from "@/features/overview/needsAttention";
import type { UpdateStatusResponse } from "@/features/system/api";

const NOW = new Date("2026-09-08T12:00:00.000Z");
const MINUTE = 60_000;
const HOUR = 3_600_000;
const DAY = 24 * HOUR;
const ago = (ms: number): string => new Date(NOW.getTime() - ms).toISOString();

const ok = <T>(value: T): Fetched<T> => ({ ok: true, value });
const denied: Fetched<never> = { ok: false, reason: "denied" };
const errored: Fetched<never> = { ok: false, reason: "error" };

const collection = (over: Partial<CollectionSummary> = {}): CollectionSummary => ({
  id: 1,
  mdmConnectionId: 1,
  name: "Full device sweep",
  kind: "device_sweep",
  enabled: true,
  nextDueAt: null,
  lastRunAt: null,
  lastRunStatus: null,
  lastSuccessAt: null,
  staleAfterSeconds: null,
  createdAt: ago(30 * DAY),
  ...over
});

const destination = (over: Partial<Destination> = {}): Destination => ({
  id: 1,
  name: "Splunk",
  type: "splunk_hec",
  url: "https://splunk.example:8088/services/collector",
  authType: "splunk_hec",
  authHeaderName: null,
  elasticIndex: null,
  hasSecret: true,
  enabled: true,
  subscribedEvents: null,
  lastError: null,
  pendingCount: 0,
  failedCount: 0,
  lastSuccessAt: null,
  lastFailureAt: null,
  createdAt: ago(DAY),
  updatedAt: ago(DAY),
  ...over
});

const connection = (over: Partial<MdmConnection> = {}): MdmConnection => ({ id: 1, name: "Jamf Pro", ...over }) as MdmConnection;

const update = (over: Partial<UpdateStatusResponse> = {}): UpdateStatusResponse => ({
  enabled: true,
  currentVersion: "abc1234",
  updateAvailable: false,
  latestSha: null,
  checkedAt: ago(HOUR),
  ...over
});

const alert = (over: Partial<Alert> = {}): Alert =>
  ({
    id: 1,
    kind: "new_app",
    level: "high",
    deviceId: 7,
    deviceLabel: "kyle-mbp",
    appHash: "hash",
    appName: "Wireshark",
    bundleId: "org.wireshark.Wireshark",
    openedAt: ago(HOUR),
    closedAt: null,
    ...over
  }) as Alert;

const alerts = (items: Alert[] = [], total = items.length): AlertListResponse => ({ items, total, page: 1, pageSize: 5 });

const inputs = (over: Partial<AttentionInputs> = {}): AttentionInputs => ({
  now: NOW,
  collections: ok([]),
  connections: ok([connection()]),
  destinations: ok([]),
  update: ok(update()),
  alerts: ok(alerts()),
  ...over
});

describe("the all-clear", () => {
  it("a quiet fleet has no rows, nothing degraded, and an attestation stamp", () => {
    const result = composeAttention(inputs());
    expect(result.rows).toEqual([]);
    expect(result.degraded).toEqual([]);
    expect(result.blind).toBe(false);
    expect(result.total).toBe(0);
    expect(result.dropped).toBe(0);
    expect(result.checkedAt).toBe("2026-09-08T12:00:00.000Z");
    expect(isAllClear(result)).toBe(true);
  });
});

describe("collection overdue — nothing ever claimed it", () => {
  it("an hour of grace: 59 minutes late is not a row, 61 minutes is", () => {
    expect(OVERDUE_GRACE_MS).toBe(HOUR);
    const early = composeAttention(inputs({ collections: ok([collection({ nextDueAt: ago(59 * MINUTE) })]) }));
    expect(early.rows).toEqual([]);
    const late = composeAttention(inputs({ collections: ok([collection({ nextDueAt: ago(61 * MINUTE) })]) }));
    expect(late.rows.map((row) => [row.kind, row.level, row.subject, row.context, row.count])).toEqual([
      ["collection_overdue", "normal", "Full device sweep", "Jamf Pro", 1]
    ]);
    expect(late.rows[0].id).toBe("collection_overdue:1");
    expect(late.rows[0].href).toBe("/settings/connections");
  });

  it("exactly the grace is still inside it", () => {
    const result = composeAttention(inputs({ collections: ok([collection({ nextDueAt: ago(60 * MINUTE) })]) }));
    expect(result.rows).toEqual([]);
  });

  it("a disabled collection is never asked about", () => {
    const result = composeAttention(inputs({ collections: ok([collection({ enabled: false, nextDueAt: ago(DAY) })]) }));
    expect(result.rows).toEqual([]);
  });

  it("two overdue collections collapse to one row for the storm, dated by the oldest", () => {
    const result = composeAttention(
      inputs({
        collections: ok([
          collection({ id: 1, nextDueAt: ago(2 * HOUR) }),
          collection({ id: 2, name: "Smart group definitions", kind: "catalog", nextDueAt: ago(5 * HOUR) })
        ])
      })
    );
    expect(result.rows).toHaveLength(1);
    expect(result.rows[0]).toMatchObject({ id: "collection_overdue:all", kind: "collection_overdue", subject: null, count: 2, at: ago(5 * HOUR) });
  });
});

describe("inventory stale — twice the cadence, measured from the last success", () => {
  const twoDays = 2 * DAY / 1000;

  it("47 hours since success is fresh at a 48-hour window; 49 is stale", () => {
    const fresh = composeAttention(inputs({ collections: ok([collection({ staleAfterSeconds: twoDays, lastSuccessAt: ago(47 * HOUR) })]) }));
    expect(fresh.rows).toEqual([]);
    const stale = composeAttention(inputs({ collections: ok([collection({ staleAfterSeconds: twoDays, lastSuccessAt: ago(49 * HOUR) })]) }));
    expect(stale.rows.map((row) => [row.id, row.level, row.subject, row.at])).toEqual([
      ["inventory_stale:1", "high", "Full device sweep", ago(49 * HOUR)]
    ]);
  });

  it("a collection that never succeeded is measured from its creation, and carries no instant", () => {
    const young = composeAttention(inputs({ collections: ok([collection({ staleAfterSeconds: twoDays, createdAt: ago(4 * MINUTE) })]) }));
    expect(young.rows).toEqual([]);
    const old = composeAttention(inputs({ collections: ok([collection({ staleAfterSeconds: twoDays, createdAt: ago(49 * HOUR) })]) }));
    expect(old.rows).toHaveLength(1);
    expect(old.rows[0].at).toBeNull();
  });

  it("only enabled device sweeps with a cadence make a staleness claim", () => {
    const result = composeAttention(
      inputs({
        collections: ok([
          collection({ id: 1, kind: "catalog", staleAfterSeconds: twoDays, lastSuccessAt: ago(10 * DAY) }),
          collection({ id: 2, enabled: false, staleAfterSeconds: twoDays, lastSuccessAt: ago(10 * DAY) }),
          collection({ id: 3, kind: "webhook", staleAfterSeconds: null, lastSuccessAt: ago(10 * DAY) })
        ])
      })
    );
    expect(result.rows).toEqual([]);
  });

  it("two stale collections collapse to one outage, as old as its longest silence", () => {
    const result = composeAttention(
      inputs({
        collections: ok([
          collection({ id: 1, staleAfterSeconds: twoDays, lastSuccessAt: ago(3 * DAY) }),
          collection({ id: 2, name: "Second sweep", staleAfterSeconds: twoDays, lastSuccessAt: ago(5 * DAY) })
        ])
      })
    );
    expect(result.rows).toHaveLength(1);
    expect(result.rows[0]).toMatchObject({ id: "inventory_stale:all", count: 2, subject: null, at: ago(5 * DAY) });
  });

  it("a stale collection's failed run is the same problem, not a second row", () => {
    const result = composeAttention(
      inputs({
        collections: ok([
          collection({ staleAfterSeconds: twoDays, lastSuccessAt: ago(5 * DAY), lastRunStatus: "failed", lastRunAt: ago(HOUR) })
        ])
      })
    );
    expect(result.rows.map((row) => row.kind)).toEqual(["inventory_stale"]);
  });
});

describe("run failed — the collection's own last outcome", () => {
  it("a failed last run is a high row dated by the attempt", () => {
    const result = composeAttention(inputs({ collections: ok([collection({ lastRunStatus: "failed", lastRunAt: ago(8 * HOUR) })]) }));
    expect(result.rows.map((row) => [row.id, row.level, row.at])).toEqual([["run_failed:1", "high", ago(8 * HOUR)]]);
  });

  it("ok, skipped, never-run and disabled are all silent", () => {
    const result = composeAttention(
      inputs({
        collections: ok([
          collection({ id: 1, lastRunStatus: "ok", lastRunAt: ago(HOUR) }),
          collection({ id: 2, lastRunStatus: "skipped", lastRunAt: ago(HOUR) }),
          collection({ id: 3 }),
          collection({ id: 4, enabled: false, lastRunStatus: "failed", lastRunAt: ago(HOUR) })
        ])
      })
    );
    expect(result.rows).toEqual([]);
  });

  it("the starvation repro: five failed collections beside a dead pipe still show the pipe", () => {
    const failed = [1, 2, 3, 4, 5].map((id) => collection({ id, name: `Sweep ${id}`, lastRunStatus: "failed", lastRunAt: ago(8 * HOUR) }));
    const result = composeAttention(
      inputs({ collections: ok(failed), destinations: ok([destination({ lastFailureAt: ago(5 * MINUTE) })]) })
    );
    expect(result.rows.map((row) => row.id)).toEqual(["run_failed:all", "destination_failing:1"]);
    expect(result.rows[0]).toMatchObject({ count: 5, at: ago(8 * HOUR), subject: null });
    expect(result.dropped).toBe(0);
  });
});

describe("destination failing — evidence is not reaching the SIEM", () => {
  it("a failure newer than the last success, or with no success at all", () => {
    const neverSucceeded = composeAttention(inputs({ destinations: ok([destination({ lastFailureAt: ago(5 * MINUTE) })]) }));
    expect(neverSucceeded.rows.map((row) => [row.kind, row.level, row.subject, row.href])).toEqual([
      ["destination_failing", "high", "Splunk", "/settings/destinations"]
    ]);
    const recovered = composeAttention(
      inputs({ destinations: ok([destination({ lastFailureAt: ago(10 * MINUTE), lastSuccessAt: ago(MINUTE) })]) })
    );
    expect(recovered.rows).toEqual([]);
    const relapsed = composeAttention(
      inputs({ destinations: ok([destination({ lastFailureAt: ago(MINUTE), lastSuccessAt: ago(10 * MINUTE) })]) })
    );
    expect(relapsed.rows).toHaveLength(1);
  });

  it("a disabled destination is not reported every time the front page opens", () => {
    const result = composeAttention(inputs({ destinations: ok([destination({ enabled: false, lastFailureAt: ago(MINUTE) })]) }));
    expect(result.rows).toEqual([]);
  });
});

describe("update available — true only", () => {
  it("true is a low row naming the short sha, with no page to send anyone to", () => {
    const result = composeAttention(inputs({ update: ok(update({ updateAvailable: true, latestSha: "abcdef1234567", checkedAt: ago(HOUR) })) }));
    expect(result.rows).toHaveLength(1);
    expect(result.rows[0]).toMatchObject({ id: "update_available:abcdef1234567", level: "low", subject: "abcdef1", href: null, at: ago(HOUR) });
  });

  it("null is unknown and indistinguishable from current", () => {
    expect(composeAttention(inputs({ update: ok(update({ updateAvailable: null })) })).rows).toEqual([]);
    expect(composeAttention(inputs({ update: ok(update({ updateAvailable: false })) })).rows).toEqual([]);
  });
});

describe("new app — the latch that closes itself", () => {
  it("a row per open latch, at the level the backend graded, linking to the change on that Mac", () => {
    const result = composeAttention(inputs({ alerts: ok(alerts([alert({ level: "normal", deviceLabel: "kyle mbp" })])) }));
    expect(result.rows).toHaveLength(1);
    expect(result.rows[0]).toMatchObject({
      id: "new_app:1",
      kind: "new_app",
      level: "normal",
      subject: "Wireshark",
      context: "kyle mbp",
      href: "/devices/changes?artifact=Wireshark&q=kyle%20mbp"
    });
  });

  it("latches the bounded page never fetched are counted as dropped, not swallowed", () => {
    const result = composeAttention(inputs({ alerts: ok(alerts([alert()], 2000)) }));
    expect(result.rows).toHaveLength(1);
    expect(result.dropped).toBe(1999);
  });
});

describe("ordering and the cap", () => {
  it("level blocks, then rank, then oldest first, then rows with no instant", () => {
    const result = composeAttention(
      inputs({
        destinations: ok([
          destination({ id: 1, name: "Blip", lastFailureAt: ago(5 * MINUTE) }),
          destination({ id: 2, name: "Dead for days", lastFailureAt: ago(3 * DAY) })
        ]),
        collections: ok([collection({ nextDueAt: ago(2 * HOUR) })]),
        update: ok(update({ updateAvailable: true, latestSha: "abcdef1234567" })),
        alerts: ok(alerts([alert({ openedAt: ago(10 * DAY) })]))
      })
    );
    expect(result.rows.map((row) => row.id)).toEqual([
      "destination_failing:2",
      "destination_failing:1",
      "new_app:1",
      "collection_overdue:1",
      "update_available:abcdef1234567"
    ]);
  });

  it("at most five rows, the rest counted, the badge counting all of them", () => {
    const failing = [1, 2, 3, 4, 5, 6, 7].map((id) => destination({ id, name: `SIEM ${id}`, lastFailureAt: ago(id * HOUR) }));
    const result = composeAttention(inputs({ destinations: ok(failing) }));
    expect(MAX_ROWS).toBe(5);
    expect(result.rows).toHaveLength(5);
    expect(result.dropped).toBe(2);
    expect(result.total).toBe(7);
    expect(isAllClear(result)).toBe(false);
  });
});

describe("degraded versus denied — the attestation gate", () => {
  it("a check that errored withholds the all-clear and is counted into the badge", () => {
    const result = composeAttention(inputs({ collections: errored }));
    expect(result.degraded).toEqual(["run_failed", "collection_overdue", "inventory_stale"]);
    expect(result.rows).toEqual([]);
    expect(result.total).toBe(3);
    expect(result.blind).toBe(false);
    expect(isAllClear(result)).toBe(false);
  });

  it("a check the session may not run is silent and does not withhold the all-clear", () => {
    const result = composeAttention(inputs({ collections: denied, alerts: denied }));
    expect(result.degraded).toEqual([]);
    expect(result.blind).toBe(false);
    expect(result.total).toBe(0);
    expect(isAllClear(result)).toBe(true);
  });

  it("every check denied is blind: no finding of any kind, and no all-clear either", () => {
    const result = composeAttention(inputs({ collections: denied, destinations: denied, update: denied, alerts: denied }));
    expect(result.blind).toBe(true);
    expect(result.degraded).toEqual([]);
    expect(result.total).toBe(0);
    expect(isAllClear(result)).toBe(false);
  });

  it("connections are names, not a check: losing them costs a row its context and nothing else", () => {
    const result = composeAttention(
      inputs({ connections: errored, collections: ok([collection({ nextDueAt: ago(2 * HOUR) })]) })
    );
    expect(result.degraded).toEqual([]);
    expect(result.rows).toHaveLength(1);
    expect(result.rows[0].context).toBeNull();
    const deniedNames = composeAttention(inputs({ connections: denied }));
    expect(deniedNames.blind).toBe(false);
  });
});
