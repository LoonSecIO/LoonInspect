import { useState } from "react";
import { Button } from "@/components/ui/button";
import { apiRequest, ApiError } from "@/config/api";
import type { PatchPlan } from "./patchPlanTypes";

const fields = [
  ["owner", "Plan owner", 255], ["window", "Maintenance window", 500], ["pilot", "Pilot scope and success criteria", 2000],
  ["recovery", "Recovery plan", 2000], ["exceptions", "Exceptions and follow-up", 4000], ["approval", "Approval / change reference", 1000],
] as const;

export function PatchPlanReview({ plan, canWrite, onDirty, onSaved }: {
  plan: PatchPlan; canWrite: boolean; onDirty: (value: boolean) => void; onSaved: (plan: PatchPlan) => void;
}) {
  const [values, setValues] = useState<Record<string, string>>(() => Object.fromEntries(fields.map(([key]) => [key, plan.snapshot.operatorReview?.[key] ?? ""])));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [dirty, setDirty] = useState(false);
  async function save() {
    setBusy(true); setError("");
    try {
      const result = await apiRequest<PatchPlan>(`/application-patch-plans/${plan.id}`, { method: "PATCH", json: { ...values, revision: plan.revision } });
      onDirty(false); onSaved(result);
    } catch (e) { setError(e instanceof ApiError && e.detail ? e.detail : "Review notes could not be saved. Check connectivity and retry."); }
    finally { setBusy(false); }
  }
  return <details className="rounded-md border p-4"><summary className="cursor-pointer font-medium">Operator review, ownership and approval</summary>
    <p className="my-3 text-sm text-muted-foreground">Record the decisions that make this plan ready for your change process. Saved notes are included in the PDF.</p>
    <div className="grid gap-3 md:grid-cols-2">{fields.map(([key, label, limit]) => <label key={key} className="grid gap-1 text-sm">{label}
      <textarea className="rounded-md border bg-background p-2" rows={key === "owner" || key === "window" ? 2 : 3} maxLength={limit}
        value={values[key]} disabled={!canWrite || busy || plan.researchStatus === "running"} placeholder="Not recorded"
        onChange={e => { setValues({ ...values, [key]: e.target.value }); setDirty(true); onDirty(true); }} />
    </label>)}</div>
    {canWrite && <Button className="mt-3" disabled={!dirty || busy || plan.researchStatus === "running"} onClick={() => void save()}>{busy ? "Saving…" : "Save review notes"}</Button>}
    {dirty && <p className="mt-2 text-sm" role="status">Unsaved review notes. Save them before exporting.</p>}
    {plan.snapshot.operatorReview?.recordedAt && <p className="mt-2 text-sm text-muted-foreground">Last recorded by {plan.snapshot.operatorReview.recordedBy} · {new Date(plan.snapshot.operatorReview.recordedAt).toLocaleString()}</p>}
    {error && <p role="alert" className="mt-2 text-sm text-destructive">{error}</p>}
  </details>;
}
