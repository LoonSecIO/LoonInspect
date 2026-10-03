import { useState } from "react";
import { Link } from "react-router";
import { Button } from "@/components/ui/button";
import { ApiError } from "@/config/api";
import { useHasPermission } from "@/features/auth/store";
import { PERMISSIONS } from "@/features/auth/types";
import { deletePatchingOverride, putPatchingOverride } from "@/features/jamfPatch/api";
import { draftOf, EMPTY_DRAFT, judges, ruleOf, type DraftProblem, type RuleDraft } from "@/features/jamfPatch/policyRules";
import { RuleFields, RuleSentences } from "@/features/jamfPatch/RuleFields";
import type { JamfPatchTitleDetail } from "@/features/jamfPatch/types";
import { useLocale } from "@/i18n/LocaleContext";

/**
 * Which patching rule judges this title, and the title's own rule where it has one.
 *
 * A title is judged by the organization's rule unless it carries an override, which
 * **replaces** that rule for this title — other limits, or `exempt`. Exempt is said in
 * words and is never counted as within policy: it is a title nobody is judging. With no rule
 * at all the card says so and points at where one is confirmed, rather than leaving the
 * versions below to look as if they had passed something.
 *
 * Editing is gated on `system:write`, like the organization's rule. `onChanged` re-reads the
 * title, because every verdict on the page is the API's and none is recomputed here.
 */
export function TitlePolicyCard({ title, onChanged }: { title: JamfPatchTitleDetail; onChanged: () => void }) {
  const { t } = useLocale();
  const copy = t.jamfPatch.rules;
  const canEdit = useHasPermission(PERMISSIONS.SYSTEM_WRITE);
  const policy = title.policy;
  const own = policy?.source === "override";

  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState<RuleDraft>(EMPTY_DRAFT);
  const [exempt, setExempt] = useState(false);
  const [problem, setProblem] = useState<DraftProblem | "empty" | null>(null);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  function startEditing() {
    // Opens on the rule in force, so "30 days instead of 14" is one edit, not a retype.
    setDraft(draftOf(policy && !policy.exempt ? policy : null));
    setExempt(policy?.exempt ?? false);
    setProblem(null);
    setError(null);
    setEditing(true);
  }

  async function run(action: () => Promise<unknown>) {
    setSaving(true);
    setError(null);
    try {
      await action();
      setEditing(false);
      onChanged();
    } catch (caught) {
      setError(caught instanceof ApiError && caught.detail ? caught.detail : copy.saveError);
    } finally {
      setSaving(false);
    }
  }

  function save() {
    if (exempt) {
      setProblem(null);
      void run(() => putPatchingOverride(title.id, { exempt: true }));
      return;
    }
    const read = ruleOf(draft);
    if ("problem" in read) {
      setProblem(read.problem);
      return;
    }
    if (!judges(read.rule)) {
      setProblem("empty");
      return;
    }
    setProblem(null);
    void run(() => putPatchingOverride(title.id, read.rule));
  }

  return (
    <div className="space-y-2 rounded-lg border bg-card p-4 text-sm">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h2 className="text-lg font-semibold">{copy.titleHeading}</h2>
        {canEdit && !editing && (
          <div className="flex gap-2">
            <Button variant="outline" size="sm" onClick={startEditing}>
              {own ? copy.editOwn : copy.giveOwn}
            </Button>
            {own && (
              <Button variant="outline" size="sm" disabled={saving} onClick={() => void run(() => deletePatchingOverride(title.id))}>
                {copy.useDefault}
              </Button>
            )}
          </div>
        )}
      </div>

      {!editing && policy === null && (
        <p className="text-muted-foreground">
          {copy.titleNone}{" "}
          <Link className="underline" to="/devices/applications/jamf-patch">
            {copy.titleNoneLink}
          </Link>
        </p>
      )}
      {!editing && policy !== null && policy.exempt && <p>{copy.titleExempt}</p>}
      {!editing && policy !== null && !policy.exempt && (
        <>
          <p>{own ? copy.titleOwnIntro : copy.titleDefaultIntro}</p>
          <RuleSentences rule={policy} t={t} />
          {policy.severityAnswering === false && <p>{copy.severityNotAnswering}</p>}
          {title.devicesOutOfPolicy !== null && (
            <p className="flex items-center gap-1.5 font-medium">
              {title.devicesOutOfPolicy > 0 && <span className="h-2 w-2 shrink-0 rounded-full bg-[#d03b3b]" />}
              {copy.titleSummary(title.devicesOutOfPolicy, title.deviceCount)}
            </p>
          )}
        </>
      )}

      {editing && (
        <div className="space-y-2">
          <p>{copy.titleOwnEditIntro}</p>
          <label className="flex items-center gap-2">
            <input type="checkbox" checked={exempt} disabled={saving} onChange={(event) => setExempt(event.target.checked)} />
            {copy.exemptLabel}
          </label>
          <RuleFields
            draft={draft}
            onChange={setDraft}
            problem={problem === "empty" ? null : problem}
            disabled={saving || exempt}
            t={t}
          />
          {problem === "empty" && <p className="text-destructive">{copy.problemEmptyOverride}</p>}
          {error && <p className="text-destructive">{error}</p>}
          <div className="flex gap-2">
            <Button size="sm" disabled={saving} onClick={save}>
              {copy.save}
            </Button>
            <Button variant="outline" size="sm" disabled={saving} onClick={() => setEditing(false)}>
              {t.jamfPatch.policy.cancel}
            </Button>
          </div>
        </div>
      )}
      {!editing && error && <p className="text-destructive">{error}</p>}
    </div>
  );
}
