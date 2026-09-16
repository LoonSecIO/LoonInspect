import { describePatchAnswer, type PatchAnswer, type TitleLine } from "@/features/catalog/patchAnswer";
import type { AppUpdate, AppVulnerability } from "@/features/vulnerabilities/types";

/**
 * What a cell prints beside a build's findings when an update would change them (#482) —
 * pure, so the rules are pinned in the frontend test lane rather than checked by eye, for
 * the reason `patchAnswer.ts` gives.
 *
 * **One line per named title.** The answer has a subject and the columns sit next to each
 * other as if it did not (#311/#313): on Wireshark 4.2.0, "Wireshark" names 4.6.8 and
 * "Wireshark 4.2" names 4.2.14, and a difference printed against one of them is true of
 * neither if it is read as the other's. So this returns a LIST, each entry carrying the
 * title that names its release, and a cell renders one line per entry. The stored answer
 * carries one target today — the reference title's `latestVersion`, which is the one
 * `describePatchAnswer` already names a subject for — so the list holds at most one line,
 * and it is attributed rather than floated.
 *
 * **Nothing at all unless the build itself is `covered`.** §4g's three renderings do not
 * collapse and this is not a fourth state: `off` and `unknown_app` carry no counts, so
 * there is nothing for an update to close, and printing a difference there would be
 * reading a count off a row nobody answered.
 */
export interface UpdateLine {
  /** The release the update would land on. */
  version: string;
  /** The matched title that names that release, when more than one title matched. */
  subject: TitleLine | null;
  /** The corpus holds no row for the target: *outside the corpus*, never *closes all*. */
  unknown: boolean;
  /** Exact — a difference of the two id lists — and present only when neither was capped. */
  closes: number | null;
  opens: number | null;
  /** The difference of the uncapped totals, for a capped pair. Positive closes findings. */
  net: number | null;
}

export function describeUpdate(
  vuln: AppVulnerability,
  update: AppUpdate | null | undefined,
  answer: PatchAnswer
): UpdateLine[] {
  if (vuln.assessment !== "covered" || !update) return [];
  const latest = describePatchAnswer(answer)?.latest ?? null;
  return [
    {
      version: update.version,
      // Only the subject for THIS release. A subject read off a patch answer that has
      // moved since the row was judged would name the wrong title, which is the exact
      // misreading #311 exists to remove.
      subject: latest && latest.version === update.version ? latest.subject : null,
      unknown: update.assessment === "unknown_app",
      closes: update.closes,
      opens: update.opens,
      net: update.net
    }
  ];
}
