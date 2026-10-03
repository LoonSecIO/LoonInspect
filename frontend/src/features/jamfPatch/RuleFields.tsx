import type { DraftProblem, RuleDraft } from "@/features/jamfPatch/policyRules";
import type { Translations } from "@/i18n/en";

const fieldClasses =
  "w-20 rounded-md border border-input bg-background px-2 py-1 text-sm tabular-nums focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:opacity-50";

/**
 * The three limits a patching rule is written in, as the sentences they mean — the whole of
 * the vocabulary, so there is nothing to type that the product cannot judge. Shared by the
 * organization's rule and a title's own; an empty box is "no limit".
 */
export function RuleFields({
  draft,
  onChange,
  problem,
  disabled,
  t
}: {
  draft: RuleDraft;
  onChange: (draft: RuleDraft) => void;
  problem: DraftProblem | null;
  disabled?: boolean;
  t: Translations;
}) {
  const copy = t.jamfPatch.rules;
  return (
    <div className="space-y-2">
      <label className="flex flex-wrap items-center gap-2">
        {copy.fieldDaysBefore}
        <input
          className={fieldClasses}
          inputMode="numeric"
          value={draft.days}
          disabled={disabled}
          aria-invalid={problem === "days"}
          onChange={(event) => onChange({ ...draft, days: event.target.value })}
        />
        {copy.fieldDaysAfter}
      </label>
      <label className="flex flex-wrap items-center gap-2">
        {copy.fieldSevereBefore}
        <input
          className={fieldClasses}
          inputMode="numeric"
          value={draft.severeDays}
          disabled={disabled}
          aria-invalid={problem === "severeDays" || problem === "severeLooser"}
          onChange={(event) => onChange({ ...draft, severeDays: event.target.value })}
        />
        {copy.fieldSevereAfter}
      </label>
      <label className="flex flex-wrap items-center gap-2">
        {copy.fieldReleasesBefore}
        <input
          className={fieldClasses}
          inputMode="numeric"
          value={draft.releases}
          disabled={disabled}
          aria-invalid={problem === "releases"}
          onChange={(event) => onChange({ ...draft, releases: event.target.value })}
        />
        {copy.fieldReleasesAfter}
      </label>
      {problem && <p className="text-destructive">{copy.problems[problem]}</p>}
      <p className="text-xs text-muted-foreground">{copy.fieldsHint}</p>
    </div>
  );
}

/** A rule's limits as the sentences they mean, one a line. Nothing for a rule with none. */
export function RuleSentences({
  rule,
  t
}: {
  rule: { maxDaysBehind: number | null; maxReleasesBehind: number | null; maxDaysBehindSevere: number | null };
  t: Translations;
}) {
  const copy = t.jamfPatch.rules;
  return (
    <ul className="list-disc space-y-0.5 pl-5">
      {rule.maxDaysBehindSevere !== null && <li>{copy.sentenceSevere(rule.maxDaysBehindSevere)}</li>}
      {rule.maxDaysBehind !== null && (
        <li>{copy.sentenceDays(rule.maxDaysBehind, rule.maxDaysBehindSevere !== null)}</li>
      )}
      {rule.maxReleasesBehind !== null && <li>{copy.sentenceReleases(rule.maxReleasesBehind)}</li>}
    </ul>
  );
}
