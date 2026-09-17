import { describe, expect, it } from "vitest";
import { rollUpDeviceApps } from "./deviceRollup";
import type { AppVulnerability } from "./types";

const covered = (total: number, kev = 0): AppVulnerability => ({
  assessment: "covered",
  corpusAsOf: "2026-09-13",
  counts: { total, kev, severity: { critical: 0, high: total, medium: 0, low: 0 } },
  daysOldestPublished: { total: total > 0 ? 400 : null, severity: { critical: null, high: null, medium: null, low: null } },
  vulnIDs: [],
  vulnIDsTruncated: false
});

const OUTSIDE: AppVulnerability = { assessment: "unknown_app", corpusAsOf: "2026-09-13" };
const OFF: AppVulnerability = { assessment: "off" };

const mac = (...vulns: AppVulnerability[]) => vulns.map((vuln) => ({ vuln }));

describe("rollUpDeviceApps", () => {
  it("counts apps and never sums findings across them", () => {
    // Wireshark 4.2.0 is 17 and the other build is 3: this Mac is *2 apps with findings*,
    // and 20 is the per-Mac number nobody ruled that this file exists to refuse.
    const rollup = rollUpDeviceApps(mac(covered(17), covered(3)));
    expect(rollup).toEqual({ withFindings: 2, onKev: 0, outsideCorpus: 0 });
  });

  it("counts KEV as apps too, and leaves a clean covered build out of both", () => {
    // `covered` with zero findings is the one state that may read as zero — we looked.
    const rollup = rollUpDeviceApps(mac(covered(17, 2), covered(4, 1), covered(0)));
    expect(rollup).toEqual({ withFindings: 2, onKev: 2, outsideCorpus: 0 });
  });

  it("carries the unknowns beside the zero, so a Mac nobody could assess is not a clean bill", () => {
    // §4a in three numbers: 0 apps with findings is true, and on its own it is the lie.
    const rollup = rollUpDeviceApps(mac(...Array.from({ length: 12 }, () => OUTSIDE)));
    expect(rollup).toEqual({ withFindings: 0, onKev: 0, outsideCorpus: 12 });
  });

  it("answers null when nothing looked, and null for a Mac with no apps", () => {
    // Nothing answering, so the caller renders nothing at all — not three zeros under a
    // banner that has just said there is no corpus and no date.
    expect(rollUpDeviceApps(mac(OFF, OFF, OFF))).toBeNull();
    expect(rollUpDeviceApps([])).toBeNull();
  });
});
