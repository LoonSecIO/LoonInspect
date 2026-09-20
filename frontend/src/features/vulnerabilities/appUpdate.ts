import { describePatchAnswer, type PatchAnswer, type TitleLine } from "@/features/catalog/patchAnswer";
import type { AppTitleUpdate, AppUpdate, AppVulnerability } from "@/features/vulnerabilities/types";

/**
 * What a cell prints beside a build's findings when an update would change them (#482) —
 * pure, so the rules are pinned in the frontend test lane rather than checked by eye, for
 * the reason `patchAnswer.ts` gives.
 *
 * Each named title carries its own stored target (#526), reference title first. The
 * legacy singular answer remains a fallback while an existing catalog awaits re-matching.
 * Equal version strings on different titles remain separate, attributed lines.
 *
 * **Nothing at all unless the build itself is `covered`.** §4g's three renderings do not
 * collapse and this is not a fourth state: `off` and `unknown_app` carry no counts, so
 * there is nothing to close and a difference there would be a count read off a row nobody
 * answered.
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

/** What the *Closes* column prints for one ranked row (#532) — #482's two renderings and no
 *  third, over the line `describeUpdate` built. The row names the release in its own *Update
 *  to* column, so the version is not repeated here.
 *
 *  `null` is the honest answer for a target the corpus holds no row for: the ranking excludes
 *  those rows server-side, so it does not arrive, and if it ever did the cell would print
 *  nothing rather than a number about a release nobody assessed (R-D). */
export interface ClosesCell {
  text: string;
  /** Present on `net` alone: the sentence saying the difference is of the totals, not the
   *  lists, because a set difference over a capped list under-reports. */
  hint: string | null;
}

export function closesCell(
  line: UpdateLine | undefined,
  copy: { closesExact: (closes: number, opens: number) => string; closesNet: (net: number) => string; updateNetHint: string }
): ClosesCell | null {
  if (!line || line.unknown) return null;
  // Exact says BOTH directions: the newer build can carry more, and a column headed *Closes*
  // that printed only the closing half would sell every update on the page.
  if (line.closes !== null && line.opens !== null) return { text: copy.closesExact(line.closes, line.opens), hint: null };
  if (line.net !== null) return { text: copy.closesNet(line.net), hint: copy.updateNetHint };
  return null;
}

export function describeUpdate(
  vuln: AppVulnerability,
  update: AppUpdate | null | undefined,
  answer: PatchAnswer,
  titles?: AppTitleUpdate[]
): UpdateLine[] {
  if (vuln.assessment !== "covered") return [];
  if (titles?.length) return titles.map((target) => ({
    version: target.version,
    subject: { id: target.titleId, name: target.titleName },
    unknown: target.assessment === "unknown_app",
    closes: target.closes, opens: target.opens, net: target.net
  }));
  if (!update) return [];
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
