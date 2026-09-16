import { Link } from "react-router";
import { describePatchAnswer, namedTitles, type PatchAnswer, type PatchState, type TitleLine } from "@/features/catalog/patchAnswer";
import { PATCH_STATE_COLORS } from "@/features/catalog/patchState";
import type { Translations } from "@/i18n/en";

function formatDay(value: string | null): string {
  return value ? new Date(value).toLocaleDateString() : "—";
}

function titleHref(id: string): string {
  return `/devices/applications/jamf-patch/${encodeURIComponent(id)}`;
}

/** A title by name, or its id in a monospace face with a hint when the catalog could not
 *  name it — never the id passed off as a name. */
function TitleName({ title, t }: { title: TitleLine; t: Translations }) {
  if (title.name !== null) return <>{title.name}</>;
  return (
    <span className="font-mono" title={t.catalog.titleNameNotRead}>
      {title.id}
    </span>
  );
}

/** " · Wireshark 4.2" after a half of the answer, with the hint saying which half it
 *  governs. Nothing at all when the describer named no subject (one title matched). The
 *  space after the dot does not break, so a narrow column wraps before the dot and the
 *  next line starts with it, rather than leaving it dangling at the end of the last. */
export function Subject({ title, hint, t }: { title: TitleLine | null; hint: (name: string) => string; t: Translations }) {
  if (title === null) return null;
  return (
    <span title={hint(title.name ?? title.id)}>
      {" \u00b7\u00a0"}
      <TitleName title={title} t={t} />
    </span>
  );
}

/** Every matched title, linked to its page, comma-separated. */
export function TitleLinks({ titles, t }: { titles: TitleLine[]; t: Translations }) {
  return (
    <>
      {titles.map((title, index) => (
        <span key={title.id}>
          {index > 0 && ", "}
          <Link to={titleHref(title.id)} className="hover:underline">
            <TitleName title={title} t={t} />
          </Link>
        </span>
      ))}
    </>
  );
}

/**
 * The Jamf Patch answer in one cell (#313), painted the same way on the device page, the
 * application record and the catalog: the state, #68's sentence when a patch is
 * available, and — where the page has no column of its own for them — the latest version
 * and the titles by name. Each half names its subject when several titles matched
 * (`patchAnswer.ts`), so "14 releases missed" and "latest 4.6.8" can no longer be read as
 * one sentence about one title.
 *
 * **`assumed` is a quiet marker** — #313 item 4, ruled by Kyle on 2026-09-13. The 2026-08-22
 * ruling kept the assumption visible on purpose, and since #67 every row is judged with no
 * device facts, so a title whose requirements test an extension attribute — Jamf's scoping
 * device for Firefox vs Firefox ESR, PyCharm Community vs Professional — reads `assumed`
 * on every row it matches. Routine, so the marker is muted text with a hint rather than a
 * colour or a warning: visible to the reader who asks, invisible to the one who does not.
 */
export function PatchAnswerCell({
  answer,
  t,
  showLatest = false,
  showTitles = false,
  none
}: {
  answer: PatchAnswer;
  t: Translations;
  /** The device page has no Latest column; the catalog and the record do. */
  showLatest?: boolean;
  /** The device page and the record have no titles column; the catalog does. On the record
   *  it is the only place a build's titles are named, and builds of one app can match
   *  different titles (Wireshark 4.2.0 matches "Wireshark 4.2" too; 4.6.x does not). */
  showTitles?: boolean;
  /** What to say when no title matched; a dash where the page's other cells use one. */
  none?: string;
}) {
  const tc = t.catalog;
  const described = describePatchAnswer(answer);
  if (described === null) return <span className="text-muted-foreground">{none ?? "—"}</span>;
  const stateLabels: Record<PatchState, string> = {
    latest: tc.stateLatest,
    behind: tc.stateBehind,
    ahead: tc.stateAhead,
    unknown: tc.stateUnknown
  };
  return (
    <div className="space-y-0.5">
      <span className="inline-flex items-center gap-1.5">
        <span className="h-2 w-2 shrink-0 rounded-full" style={{ backgroundColor: PATCH_STATE_COLORS[described.state] }} />
        {stateLabels[described.state]}
        {described.assumed && (
          <span className="text-xs text-muted-foreground" title={tc.assumedHint}>
            · {tc.assumed}
          </span>
        )}
      </span>
      {described.sentence && (
        <span className="block text-xs text-muted-foreground">
          {tc.behindSince(formatDay(described.sentence.since), described.sentence.missed)}
          <Subject title={described.sentence.subject} hint={tc.sentenceSubjectHint} t={t} />
        </span>
      )}
      {showLatest && described.latest && (
        <span className="block text-xs text-muted-foreground">
          {tc.latestVersion(described.latest.version)}
          <Subject title={described.latest.subject} hint={tc.latestSubjectHint} t={t} />
        </span>
      )}
      {showTitles && described.titles.length > 0 && (
        <span className="block text-xs">
          <TitleLinks titles={described.titles} t={t} />
        </span>
      )}
    </div>
  );
}

/** The Latest column on the pages that have one: the version, and under it its title when
 *  several matched — the half of the Wireshark misreading that lives in this column. */
export function LatestCell({ answer, t }: { answer: PatchAnswer; t: Translations }) {
  const described = describePatchAnswer(answer);
  if (!described?.latest) return <span className="text-muted-foreground">—</span>;
  const subject = described.latest.subject;
  return (
    <div className="space-y-0.5">
      <span className="tabular-nums">{described.latest.version}</span>
      {subject && (
        <span className="block text-xs text-muted-foreground" title={t.catalog.latestSubjectHint(subject.name ?? subject.id)}>
          <TitleName title={subject} t={t} />
        </span>
      )}
    </div>
  );
}

/** The Jamf title column on the catalog: every matched title by name, or a dash. */
export function TitlesCell({ answer, t }: { answer: Pick<PatchAnswer, "jamfTitleIds" | "jamfTitles">; t: Translations }) {
  const titles = namedTitles(answer);
  if (titles.length === 0) return <span className="text-muted-foreground">—</span>;
  return <TitleLinks titles={titles} t={t} />;
}
