import { useEffect, useRef, useState } from "react";
import { Button } from "@/components/ui/button";
import { apiRequest, ApiError } from "@/config/api";
import { readReviewDraft, rememberReviewDraft, forgetReviewDraft, watchReviewDraft } from "./patchPlanDraft";
import type { PatchPlan } from "./patchPlanTypes";

const fields = [
  ["owner", "Plan owner", 255], ["window", "Maintenance window", 500], ["pilot", "Pilot scope and success criteria", 2000],
  ["recovery", "Recovery plan", 2000], ["exceptions", "Exceptions and follow-up", 4000], ["approval", "Approval / change reference", 1000],
] as const;

export function PatchPlanReview({ plan, canWrite, draftKey, onDirty, onSaved }: {
  plan: PatchPlan; canWrite: boolean; draftKey: string; onDirty: (value: boolean) => void; onSaved: (plan: PatchPlan) => void;
}) {
  const savedValues = () => Object.fromEntries(fields.map(([key]) => [key, plan.snapshot.operatorReview?.[key] ?? ""]));
  const [restored] = useState(() => canWrite ? readReviewDraft(draftKey) : null);
  const [values, setValues] = useState<Record<string, string>>(() => restored?.values ?? savedValues());
  const [draftRevision, setDraftRevision] = useState(restored?.revision ?? plan.revision);
  const [storageError, setStorageError] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [dirty, setDirty] = useState(!!restored);
  const conflicted = dirty && draftRevision !== plan.revision;
  useEffect(() => { if (restored) watchReviewDraft(draftKey); }, [draftKey, restored]);
  function remember(next: Record<string, string>) {
    setValues(next); setDirty(true); onDirty(true);
    setStorageError(!rememberReviewDraft(draftKey, { revision: draftRevision, values: next }));
  }
  function discard() {
    setStorageError(!forgetReviewDraft(draftKey));
    setValues(savedValues()); setDraftRevision(plan.revision); setDirty(false); onDirty(false);
  }
  const alive = useRef(true);
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);
  async function save() {
    setBusy(true); setError("");
    try {
      const result = await apiRequest<PatchPlan>(`/application-patch-plans/${plan.id}`, { method: "PATCH", json: { ...values, revision: plan.revision } });
      if (!alive.current) return;
      setStorageError(!forgetReviewDraft(draftKey));
      setDirty(false); onDirty(false); onSaved(result);
    } catch (e) { if (alive.current) setError(e instanceof ApiError && e.detail ? e.detail : "Review notes could not be saved. Check connectivity and retry."); }
    finally { if (alive.current) setBusy(false); }
  }
  return <details className="rounded-md border p-4"><summary className="cursor-pointer font-medium">Operator review, ownership and approval</summary>
    <p className="my-3 text-sm text-muted-foreground">Record the decisions that make this plan ready for your change process. Saved notes are included in the PDF.</p>
    <div className="grid gap-3 md:grid-cols-2">{fields.map(([key, label, limit]) => <label key={key} className="grid gap-1 text-sm">{label}
      <textarea className="rounded-md border bg-background p-2" rows={key === "owner" || key === "window" ? 2 : 3} maxLength={limit}
        value={values[key]} disabled={!canWrite || busy || plan.researchStatus === "running"} placeholder="Not recorded"
        onChange={e => remember({ ...values, [key]: e.target.value })} />
    </label>)}</div>
    {canWrite && <Button className="mt-3" disabled={!dirty || conflicted || busy || plan.researchStatus === "running"} onClick={() => void save()}>{busy ? "Saving…" : "Save review notes"}</Button>}
    {dirty && <p className="mt-2 text-sm" role="status">Unsaved review notes. {storageError ? "Browser storage is unavailable. These notes remain in memory while this tab stays open; save or copy them before closing it." : "Your draft is kept in this browser tab when you navigate away. Save it before exporting."}</p>}
    {conflicted && <p role="alert" className="mt-2 text-sm text-destructive">This draft is from revision {draftRevision}; the saved plan is now revision {plan.revision}. Copy any notes you need, then discard the draft to review the current saved notes.</p>}
    {dirty && <Button className="mt-3 ml-2" variant="ghost" disabled={busy} onClick={() => { if (window.confirm("Discard your unsaved review notes and use the saved plan?")) discard(); }}>Discard draft</Button>}
    {plan.snapshot.operatorReview?.recordedAt && <p className="mt-2 text-sm text-muted-foreground">Last recorded by {plan.snapshot.operatorReview.recordedBy} · {new Date(plan.snapshot.operatorReview.recordedAt).toLocaleString()}</p>}
    {error && <p role="alert" className="mt-2 text-sm text-destructive">{error}</p>}
  </details>;
}
