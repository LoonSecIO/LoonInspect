/** Queue depth (#468): whether either sentence above the Destinations list is said at all,
 *  and the number it carries when it is. Frontend lane (#285). */

import { describe, expect, it } from "vitest";
import { deadLetterDaysLeft, heldExpiresAt } from "@/features/destinations/queueDepth";
import type { OutboxDepth } from "@/features/destinations/types";

const NOW = new Date("2026-09-16T12:00:00Z");
const DAY = 86_400_000;
const HELD = { events: 2, oldestAgeSeconds: 5 * 86400, reason: "no_enabled_destination" as const };

function depth(over: Partial<OutboxDepth> = {}): OutboxDepth {
  return {
    held: { events: 0, oldestAgeSeconds: null, reason: null },
    pending: { deliveries: 0, oldestAgeSeconds: null },
    deadLettered: { deliveries: 0, oldestExpiresAt: null },
    retention: { eventRetentionDays: 7, deadLetterRetentionDays: 30, nextPurgeAt: "2026-09-17T07:45:00Z" },
    ...over
  };
}

/** Dead letters whose redrive window closes `ms` from NOW. */
const expiring = (ms: number): Partial<OutboxDepth> => ({
  deadLettered: { deliveries: 12, oldestExpiresAt: new Date(NOW.getTime() + ms).toISOString() }
});

describe("the empty queue", () => {
  it("says neither sentence, so a healthy stack never grows a zero to stop reading", () => {
    // `QueueDepthLines` renders nothing when both of these are empty, which is the
    // all-empty half of the done-when — asserted here, where a node-only lane can.
    expect(heldExpiresAt(depth(), NOW)).toBeNull();
    expect(deadLetterDaysLeft(depth(), NOW)).toBeNull();
  });
});

describe("heldExpiresAt", () => {
  it("dates the expiry from when the oldest event was produced, not from now", () => {
    // Five days held against a seven-day window: two days left to add a destination.
    expect(heldExpiresAt(depth({ held: HELD }), NOW)?.toISOString()).toBe("2026-09-18T12:00:00.000Z");
  });

  it("stays silent about a hold no sentence can fix — the seconds before the next tick", () => {
    expect(heldExpiresAt(depth({ held: { ...HELD, reason: null } }), NOW)).toBeNull();
  });
});

describe("deadLetterDaysLeft", () => {
  it("rounds down, so a window closing in two hours is today rather than a day away", () => {
    expect(deadLetterDaysLeft(depth(expiring(2 * 3_600_000)), NOW)).toBe(0);
    expect(deadLetterDaysLeft(depth(expiring(20 * DAY - 60_000)), NOW)).toBe(19);
    expect(deadLetterDaysLeft(depth(expiring(20 * DAY)), NOW)).toBe(20);
  });

  it("floors a deadline the daily purge has not reached yet at 0, never a negative", () => {
    expect(deadLetterDaysLeft(depth(expiring(-3 * DAY)), NOW)).toBe(0);
  });
});
