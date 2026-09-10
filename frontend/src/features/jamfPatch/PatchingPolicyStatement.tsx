import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { ApiError } from "@/config/api";
import { useHasPermission } from "@/features/auth/store";
import { PERMISSIONS } from "@/features/auth/types";
import { getPatchingPolicy, putPatchingPolicy } from "@/features/jamfPatch/api";
import type { PatchingPolicy } from "@/features/jamfPatch/types";
import { useLocale } from "@/i18n/LocaleContext";

type Loaded = { state: "ready"; policy: PatchingPolicy } | { state: "failed" };

/**
 * The org's stated patching policy, beside the evidence it is read against (#116): typed
 * text an auditor reads next to the coverage numbers and the laggards. Display and
 * evidence context only — it sets no threshold, and the boundary sentence says so on the
 * page, because a reader who sees a policy beside a number will assume the number is
 * judged against it unless told otherwise (docs/v-never.md).
 *
 * An unstated policy reads in words, and a failed read reads as a failure; the two must
 * never look alike (#150). Editing is inline and gated on `system:write`, the same gate as
 * the other tenant settings.
 */
export function PatchingPolicyStatement() {
  const { t } = useLocale();
  const tp = t.jamfPatch.policy;
  const canEdit = useHasPermission(PERMISSIONS.SYSTEM_WRITE);
  const [loaded, setLoaded] = useState<Loaded | null>(null);
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState("");
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);

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

  const policy = loaded?.state === "ready" ? loaded.policy : null;

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
          {/* The boundary, on the page and not only in the docs: a policy beside a number
              is not the number's threshold. */}
          <p className="mt-2 text-xs text-muted-foreground">{tp.boundary}</p>
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
          <p className="text-xs text-muted-foreground">{tp.boundary}</p>
        </div>
      )}
    </section>
  );
}
