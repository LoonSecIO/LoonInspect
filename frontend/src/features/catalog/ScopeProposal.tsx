import { useEffect, useRef, useState } from "react";
import { Link } from "react-router";
import { Button } from "@/components/ui/button";
import { apiRequest, ApiError } from "@/config/api";
import { readScope, type DeviceScope } from "./deviceScope";
import { scopeInput } from "./ScopeGroupEditor";

type AIStatus = { available: boolean; reason: string | null; providers: { provider: string; model: string }[] };
type Proposal = { outcome: "proposed" | "unsupported" | "unusable"; scope: DeviceScope | null; detail: string;
  matchedDevices?: number; warnings: string[]; provider: string; model: string; reportedModel?: string };

export function ScopeProposal({ scope, onLoad }: { scope: DeviceScope; onLoad: (scope: DeviceScope) => void }) {
  const [status, setStatus] = useState<AIStatus>();
  const [question, setQuestion] = useState("");
  const [provider, setProvider] = useState("");
  const [proposal, setProposal] = useState<Proposal>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [reload, setReload] = useState(0);
  const [statusInput, setStatusInput] = useState(reload);
  if (statusInput !== reload) { setStatusInput(reload); setStatus(undefined); }
  const request = useRef<AbortController | null>(null);
  useEffect(() => {
    const controller = new AbortController();
    apiRequest<AIStatus>("/application-patch-plans/ai-status", { signal: controller.signal })
      .then(value => { if (!controller.signal.aborted) setStatus(value); })
      .catch(() => { if (!controller.signal.aborted) setStatus({ available: false, reason: "unreachable", providers: [] }); });
    return () => controller.abort();
  }, [reload]);
  useEffect(() => () => request.current?.abort(), []);
  async function propose() {
    if (request.current || !question.trim()) return;
    const controller = new AbortController(); request.current = controller;
    setBusy(true); setError(""); setProposal(undefined);
    try {
      const result = await apiRequest<Proposal>("/application-patch-plans/propose-scope", {
        method: "POST", signal: controller.signal, json: { question, scope, provider: provider || status?.providers[0]?.provider || null },
      });
      if (controller.signal.aborted) return;
      if (result.scope && !readScope(JSON.stringify(result.scope))) throw new Error("invalid");
      setProposal(result);
    } catch (e) {
      if (!controller.signal.aborted) setError(e instanceof ApiError && e.detail ? e.detail : "The group proposal could not be read. Check the AI service or try a shorter request.");
    } finally { request.current = null; if (!controller.signal.aborted) setBusy(false); }
  }
  return <details className="rounded-lg border bg-muted/15 p-3">
    <summary className="cursor-pointer text-sm font-semibold">Propose a group with AI</summary>
    <div className="mt-3 space-y-3">
      <p className="text-sm text-muted-foreground">Describe the Macs to include. AI drafts a local filter for review. Applying it filters LoonInspect; it does not create a Jamf group.</p>
      {status?.available ? <>
        <textarea aria-label="Describe the proposed device group" className={`${scopeInput} w-full`} rows={3} value={question} maxLength={2000}
          placeholder="Managed Macs that contacted us within 14 days AND (are in the pilot group OR have Update Ring set to Pilot)."
          onChange={e => setQuestion(e.target.value)} />
        <div className="flex flex-wrap items-center gap-2">
          <select className={scopeInput} aria-label="Group proposal AI provider" value={provider || status.providers[0]?.provider || ""} onChange={e => setProvider(e.target.value)}>
            {status.providers.map(p => <option key={p.provider} value={p.provider}>{p.provider} · {p.model}</option>)}
          </select>
          <Button disabled={busy || !question.trim() || !readScope(JSON.stringify(scope))} onClick={() => void propose()}>{busy ? "Proposing group…" : "Propose a group"}</Button>
        </div>
        <p className="text-xs text-muted-foreground">Sends your request, draft conditions, and bounded connection/group/EA names and IDs to the selected service. Inventory device names, serial numbers and stored credentials are excluded.</p>
      </> : <p className="text-sm">{status ? `AI unavailable: ${status.reason?.replaceAll("_", " ") ?? "check settings"}.` : "Checking AI services…"}
        {" "}<Link className="underline" to="/settings/ai">AI settings</Link>{" "}<Button size="sm" variant="ghost" onClick={() => setReload(n => n + 1)}>Check again</Button>
      </p>}
      {busy && <p role="status" className="text-sm">The proposal may take up to two minutes. Your applied filter stays active.</p>}
      {error && <p role="alert" className="text-sm text-destructive">{error}</p>}
      {proposal && <div className="space-y-2 rounded-md border bg-background p-3" aria-label="AI group proposal">
        <p className="text-sm">{proposal.detail}</p>
        {proposal.warnings.map((warning, i) => <p key={i} className="text-sm text-amber-700 dark:text-amber-300">{warning}</p>)}
        {proposal.scope && <>
          <p className="text-sm font-medium">{proposal.matchedDevices?.toLocaleString()} Macs matched when proposed.</p>
          <details><summary className="cursor-pointer text-sm">Proposed JSON</summary><pre className="mt-2 max-h-80 overflow-auto whitespace-pre-wrap break-all rounded bg-muted p-3 text-xs">{JSON.stringify(proposal.scope, null, 2)}</pre></details>
          <Button variant="outline" onClick={() => { onLoad(proposal.scope!); setProposal(undefined); }}>Load proposal into builder</Button>
        </>}
        <p className="text-xs text-muted-foreground">{proposal.provider} · {proposal.reportedModel || proposal.model} · review required</p>
      </div>}
    </div>
  </details>;
}
