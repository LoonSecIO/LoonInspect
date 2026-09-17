import { assertExhaustive, type AppVulnerability } from "@/features/vulnerabilities/types";

/**
 * One Mac's apps counted three ways (#535) — the line above its apps table, and the Devices
 * list's column, from one definition.
 *
 * **Apps, never findings.** Two vulnerable builds is *2 apps with findings* and never *20*:
 * findings against different builds are not addable, each build's total already sits in its
 * own cell, and a per-Mac sum is a number nobody ruled (`docs/vulnerabilities.md` §4g).
 *
 * **The unknowns travel with the other two.** A Mac whose apps the corpus has never heard
 * of reads *0 apps with findings · 0 on KEV · 12 outside the corpus*, which is not a clean
 * bill and must not render as one (§4a) — so there is no shape here that hands a caller
 * `withFindings` without `outsideCorpus` beside it.
 */
export interface DeviceVulnRollup {
  /** Apps whose served answer is `covered` with at least one finding. */
  withFindings: number;
  /** Of those, apps carrying a finding on CISA's KEV list. */
  onKev: number;
  /** Apps the loaded corpus holds no row for — dated, uncounted, never zero findings. */
  outsideCorpus: number;
}

/**
 * The three numbers over rows the page already holds — arithmetic, not a request (§4g).
 *
 * `null` when nothing was answered: every app reads `off`, so there is no corpus and nothing
 * to count, and the caller renders **nothing at all** rather than three zeros under a banner
 * that has just said so. An empty app list answers `null` for the same reason.
 */
export function rollUpDeviceApps(apps: readonly { vuln: AppVulnerability }[]): DeviceVulnRollup | null {
  let withFindings = 0;
  let onKev = 0;
  let outsideCorpus = 0;
  let answered = false;

  for (const { vuln } of apps) {
    switch (vuln.assessment) {
      case "off":
        break;
      case "unknown_app":
        answered = true;
        outsideCorpus += 1;
        break;
      case "covered":
        answered = true;
        // `> 0` on both: a covered build with no findings is a clean bill and is counted in
        // neither number — it is the one state that may honestly read as zero.
        if (vuln.counts.total > 0) withFindings += 1;
        if (vuln.counts.kev > 0) onKev += 1;
        break;
      default:
        return assertExhaustive(vuln);
    }
  }

  return answered ? { withFindings, onKev, outsideCorpus } : null;
}
