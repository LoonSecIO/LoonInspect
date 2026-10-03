import { useEffect, useState } from "react";
import { Link } from "react-router";
import { Button } from "@/components/ui/button";
import { ApiError } from "@/config/api";
import { useHasPermission } from "@/features/auth/store";
import { PERMISSIONS } from "@/features/auth/types";
import { getPatchingPolicy, putPatchingPolicy, putPatchingRule } from "@/features/jamfPatch/api";
import { draftOf, EMPTY_DRAFT, ruleOf, type DraftProblem, type RuleDraft } from "@/features/jamfPatch/policyRules";
import { RuleFields, RuleSentences } from "@/features/jamfPatch/RuleFields";
import type { PatchingPolicy } from "@/features/jamfPatch/types";
import { useLocale } from "@/i18n/LocaleContext";

type Loaded = { state: "ready"; policy: PatchingPolicy } | { state: "failed" };

/**
 * The org's patching policy, beside the evidence it is read against: the **statement**
 * (#116), typed text an auditor reads next to the numbers, and under it the **rules** the
 * organization has confirmed.
 *
 * The two are kept apart on purpose. The statement sets no threshold — a sentence cannot be
 * evaluated, and a reader who sees a policy beside a number will assume the number is judged
 * against it unless told otherwise (docs/v-never.md). A rule is the one thing that judges:
 * limits from a closed vocabulary, confirmed by someone holding `system:write`, and the
 * boundary sentence says which is which on the page.
 *
 * An unstated policy reads in words, and a failed read reads as a failure; the two must
 * never look alike (#150). Editing is inline and gated on `system:write`, the same gate as
 * the other tenant settings. `onRulesChanged` lets the list re-read its out-of-policy counts.
 */
export function PatchingPolicyStatement({
  onRulesChanged,
  severityAnswering = null
}: {
  onRulesChanged?: () => void;
  /** From the list it sits above: false when a rule has a limit for builds with critical or
   *  high findings and no corpus is answering, so that limit is judging nothing. */
  severityAnswering?: boolean | null;
}) {
  const { t } = useLocale();
  const tp = t.jamfPatch.policy;
  const tr = t.jamfPatch.rules;
  const canEdit = useHasPermission(PERMISSIONS.SYSTEM_WRITE);
  const [loaded, setLoaded] = useState<Loaded | null>(null);
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState("");
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [editingRule, setEditingRule] = useState(false);
  const [ruleDraft, setRuleDraft] = useState<RuleDraft>(EMPTY_DRAFT);
  const [ruleProblem, setRuleProblem] = useState<DraftProblem | null>(null);
  const [ruleError, setRuleError] = useState<string | null>(null);
  useEffect(() => {
    let cancelled = false;
    getPatchingPolicy()
      .then((policy) => {
        if (!cancelled) setLoaded({ state: "ready", policy });
      })
      .catch(() => {
        if (!cancelled) setLoaded({ state: "failed" });
      });
    return () => {
      cancelled = true;
    };
  }, []);

  function startEditing() {
    setDraft(loaded?.state === "ready" ? loaded.policy.statement : "");
    setSaveError(null);
    setEditing(true);
  }

  async function save() {
    setSaving(true);
    setSaveError(null);
    try {
      const policy = await putPatchingPolicy(draft);
      setLoaded({ state: "ready", policy });
      setEditing(false);
    } catch (caught) {
      setSaveError(caught instanceof ApiError && caught.detail ? caught.detail : tp.saveError);
    } finally {
      setSaving(false);
    }
  }

  function startEditingRule() {
    setRuleDraft(draftOf(loaded?.state === "ready" ? loaded.policy.rules.default : null));
    setRuleProblem(null);
    setRuleError(null);
    setEditingRule(true);
  }

  async function saveRule() {
    const read = ruleOf(ruleDraft);
    if ("problem" in read) {
      setRuleProblem(read.problem);
      return;
    }
    setSaving(true);
    setRuleProblem(null);
    setRuleError(null);
    try {
      const policy = await putPatchingRule(read.rule);
      setLoaded({ state: "ready", policy });
      setEditingRule(false);
      onRulesChanged?.();
    } catch (caught) {
      setRuleError(caught instanceof ApiError && caught.detail ? caught.detail : tr.saveError);
    } finally {
      setSaving(false);
    }
  }

  const policy = loaded?.state === "ready" ? loaded.policy : null;
  const rules = policy?.rules ?? null;

  return (
    <section className="rounded-lg border bg-card p-4 text-sm">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h2 className="font-semibold">{tp.heading}</h2>
        {canEdit && !editing && loaded?.state === "ready" && (
          <Button variant="outline" size="sm" onClick={startEditing}>
            {policy && policy.statement ? tp.edit : tp.state}
          </Button>
        )}
      </div>
      {loaded === null && <p className="mt-2 text-muted-foreground">{tp.loading}</p>}
      {loaded?.state === "failed" && <p className="mt-2 text-destructive">{tp.errorLoading}</p>}
      {policy && !editing && (
        <>
          {policy.statement ? (
            <blockquote className="mt-2 whitespace-pre-wrap border-l-2 pl-3">{policy.statement}</blockquote>
          ) : (
            <p className="mt-2 text-muted-foreground">{tp.none}</p>
          )}
          {policy.statement && policy.updatedAt && (
            <p className="mt-1 text-xs text-muted-foreground">
              {tp.statedBy(policy.updatedBy ?? tp.unknownAuthor, new Date(policy.updatedAt).toLocaleString())}
            </p>
          )}
        </>
      )}
      {editing && (
        <div className="mt-2 space-y-2">
          <textarea
            className="min-h-[6rem] w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            value={draft}
            maxLength={4000}
            onChange={(event) => setDraft(event.target.value)}
            placeholder={tp.placeholder}
          />
          {saveError && <p className="text-destructive">{saveError}</p>}
          <div className="flex gap-2">
            <Button size="sm" disabled={saving} onClick={() => void save()}>
              {tp.save}
            </Button>
            <Button variant="outline" size="sm" disabled={saving} onClick={() => setEditing(false)}>
              {tp.cancel}
            </Button>
          </div>
        </div>
      )}

      {/* The rules: what the page judges against, and the only thing it judges against. */}
      {rules && (
        <div className="mt-4 border-t pt-3">
          <div className="flex flex-wrap items-baseline justify-between gap-2">
            <h3 className="font-semibold">{tr.heading}</h3>
            {canEdit && !editingRule && (
              <Button variant="outline" size="sm" onClick={startEditingRule}>
                {rules.default ? tr.edit : tr.confirm}
              </Button>
            )}
          </div>
          {!editingRule &&
            (rules.default ? (
              <div className="mt-2">
                <p>{tr.defaultIntro}</p>
                <RuleSentences rule={rules.default} t={t} />
              </div>
            ) : (
              <p className="mt-2 text-muted-foreground">{rules.overrides.length > 0 ? tr.noneButOverrides : tr.none}</p>
            ))}
          {editingRule && (
            <div className="mt-2 space-y-2">
              <p>{tr.defaultIntro}</p>
              <RuleFields draft={ruleDraft} onChange={setRuleDraft} problem={ruleProblem} disabled={saving} t={t} />
              {ruleError && <p className="text-destructive">{ruleError}</p>}
              <div className="flex gap-2">
                <Button size="sm" disabled={saving} onClick={() => void saveRule()}>
                  {tr.save}
                </Button>
                <Button variant="outline" size="sm" disabled={saving} onClick={() => setEditingRule(false)}>
                  {tp.cancel}
                </Button>
              </div>
            </div>
          )}
          {rules.overrides.length > 0 && (
            <div className="mt-3">
              <p>{tr.overridesIntro(rules.overrides.length)}</p>
              <ul className="list-disc space-y-0.5 pl-5">
                {rules.overrides.map((override) => (
                  <li key={override.titleId}>
                    <Link
                      className="font-medium hover:underline"
                      to={`/devices/applications/jamf-patch/${encodeURIComponent(override.titleId)}`}
                    >
                      {override.titleName ?? tr.overrideUnlisted(override.titleId)}
                    </Link>
                    {" — "}
                    {override.exempt
                      ? tr.exemptShort
                      : tr.limitsShort(override.maxDaysBehind, override.maxReleasesBehind, override.maxDaysBehindSevere)}
                  </li>
                ))}
              </ul>
            </div>
          )}
          {severityAnswering === false && !editingRule && <p className="mt-2">{tr.severityNotAnswering}</p>}
          {rules.updatedAt && (
            <p className="mt-2 text-xs text-muted-foreground">
              {tr.confirmedBy(rules.updatedBy ?? tp.unknownAuthor, new Date(rules.updatedAt).toLocaleString())}
            </p>
          )}
          {/* The boundary, on the page and not only in the docs: the statement beside a
              number is not the number's threshold; a confirmed rule is. */}
          <p className="mt-2 text-xs text-muted-foreground">{tp.boundary}</p>
        </div>
      )}
    </section>
  );
}
