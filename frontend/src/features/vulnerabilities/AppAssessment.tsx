import type { ReactNode } from "react";
import type { Translations } from "@/i18n/en";
import { assertExhaustive, formatCorpusDate, type AppVulnerability } from "@/features/vulnerabilities/types";

// Fixed status colours, never themed, per the dataviz palette the catalog's patch-state
// column already uses: good / warning / critical / neutral. `unknown_app` is the warning
// colour rather than the good one on purpose — "we did not look at this" is a gap in the
// answer, and a gap coloured green is the picture #251 exists to prevent.
const GOOD = "#0ca30c";
const WARNING = "#fab219";
const CRITICAL = "#d03b3b";

function Dot({ color }: { color: string }) {
  return <span className="h-2 w-2 shrink-0 rounded-full" style={{ backgroundColor: color }} />;
}

function Label({ color, children }: { color: string | null; children: ReactNode }) {
  return (
    <span className="inline-flex items-center gap-1.5">
      {color ? <Dot color={color} /> : null}
      {children}
    </span>
  );
}

/** How many finding ids to name before collapsing the rest into a count. */
const IDS_SHOWN = 3;

/**
 * One app's vulnerability state, for a table cell (#251).
 *
 * Three states, three renderings, and the compiler is what keeps them three: the switch is
 * exhaustive over the discriminated union, and `counts` exists on the `covered` branch
 * alone — so "0 findings" cannot be printed for an app nobody assessed even by accident.
 * That is `docs/vulnerabilities.md` §4a made structural instead of remembered.
 *
 * A clean bill and an unassessed app differ in colour, in wording and in whether they
 * carry a date: `covered` with nothing found says we looked, and when; `off` says nobody
 * looked, and shows no date at all rather than borrowing today's.
 */
export function AssessmentCell({ vuln, t }: { vuln: AppVulnerability; t: Translations }) {
  const copy = t.vulnerabilities;

  switch (vuln.assessment) {
    case "off":
      // No corpus, no answer, and no date to pretend with.
      return (
        <div className="space-y-0.5">
          <Label color={null}>
            <span className="text-muted-foreground">{copy.stateOff}</span>
          </Label>
          <span className="block text-xs text-muted-foreground">{copy.stateOffReason}</span>
        </div>
      );

    case "unknown_app":
      // Outside the corpus, dated — and deliberately not a zero.
      return (
        <div className="space-y-0.5">
          <Label color={WARNING}>{copy.stateUnknownApp}</Label>
          <span className="block text-xs text-muted-foreground">
            {copy.notInCorpusOf(formatCorpusDate(vuln.corpusAsOf))}
          </span>
        </div>
      );

    case "covered": {
      const { counts, daysOldestPublished, vulnIDs, vulnIDsTruncated } = vuln;
      const checked = copy.checkedAgainstCorpusOf(formatCorpusDate(vuln.corpusAsOf));

      if (counts.total === 0) {
        // A clean bill — honest precisely because `covered` says we looked, and dated so
        // a reader can see how old the looking is.
        return (
          <div className="space-y-0.5">
            <Label color={GOOD}>{copy.stateCoveredClean}</Label>
            <span className="block text-xs text-muted-foreground">{checked}</span>
          </div>
        );
      }

      const named = vulnIDs.slice(0, IDS_SHOWN);
      const rest = vulnIDs.length - named.length;
      return (
        <div className="space-y-0.5">
          <Label color={CRITICAL}>
            {copy.findings(counts.total)}
            {counts.kev > 0 ? <span className="text-xs font-medium">· {copy.kev(counts.kev)}</span> : null}
          </Label>
          {daysOldestPublished.total === null ? null : (
            <span className="block text-xs text-muted-foreground">
              {copy.oldestPublished(daysOldestPublished.total)}
            </span>
          )}
          <span className="block font-mono text-xs text-muted-foreground">
            {named.join(", ")}
            {rest > 0 ? ` ${copy.moreIds(rest)}` : ""}
            {/* The cap bit: the count above is every finding, the list below is not. */}
            {vulnIDsTruncated ? ` · ${copy.idsCapped}` : ""}
          </span>
          <span className="block text-xs text-muted-foreground">{checked}</span>
        </div>
      );
    }

    default:
      return assertExhaustive(vuln);
  }
}

/**
 * The corpus's edge, in words, above the rows it governs (#251).
 *
 * The stamp and the rows come from one response, so this banner can never date a column
 * the server answered from a different corpus. `corpusAsOf === null` is not an error state
 * and must not read as one: it is the honest state of every container shipping today, and
 * the copy says what is not known rather than leaving a green-looking table to imply a
 * clean fleet.
 */
export function CorpusBanner({ corpusAsOf, t }: { corpusAsOf: string | null; t: Translations }) {
  const copy = t.vulnerabilities;
  const dated = corpusAsOf === null ? null : formatCorpusDate(corpusAsOf);

  return (
    <div className="rounded-lg border bg-card p-3">
      <p className="text-sm font-medium">{dated === null ? copy.corpusHeadingNone : copy.corpusHeading(dated)}</p>
      <p className="mt-1 text-sm text-muted-foreground">{dated === null ? copy.corpusBodyNone : copy.corpusBody(dated)}</p>
      {/* The differentiator, said plainly: what the product does not know, dated. */}
      <p className="mt-1 text-sm text-muted-foreground">{dated === null ? copy.edgeNone : copy.edge(dated)}</p>
    </div>
  );
}
