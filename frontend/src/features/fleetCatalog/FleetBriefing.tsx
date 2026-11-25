import { useEffect, useId, useRef, useState } from "react";
import { Button } from "@/components/ui/button";
import { ApiError } from "@/config/api";
import type { Provider } from "@/features/ai/api";
import { failureReason, isPromptStatus, modelOptions, providerLabel } from "@/features/changes/prompt";
import type { PromptStatus } from "@/features/changes/types";
import { getBriefingStatus, requestBriefing } from "@/features/fleetCatalog/api";
import { isBriefing, type Briefing } from "@/features/fleetCatalog/briefing";
import { useLocale } from "@/i18n/LocaleContext";

/** A failed read, kept as its error so its sentence follows the locale. Null is a 200 the guard refused: unreadable. */
type Failure = { error: unknown };

/** The migration briefing (#911) under Migration review's table: a saved provider picks which of the report's own counts lead for
 *  the Macs `scope` (`fleetScopeQuery`, sent unchanged) selects. Nothing is sent until **Generate briefing** is pressed, and the
 *  answer is codes and counts worded here, so no model text reaches the page. `available: false` renders nothing, as on the
 *  Prompt bar: Settings › AI names the switch that is off. Its `key` is the query, so a new device filter aborts a request still out. */
export function FleetBriefing({ scope }: { scope: string }) {
  const { t } = useLocale();
  const copy = t.fleetPlanning.briefing;
  const tp = t.changes.prompt;
  const pickerId = useId();
  const [status, setStatus] = useState<PromptStatus>();
  const [statusFailure, setStatusFailure] = useState<Failure>();
  const [provider, setProvider] = useState<Provider>();
  const [pending, setPending] = useState(false);
  const [result, setResult] = useState<Briefing>();
  const [failure, setFailure] = useState<Failure>();
  const flight = useRef<AbortController | null>(null);
  useEffect(() => {
    const controller = new AbortController();
    // Two handlers, so only the request's own failure reads as one; a body that is not the status is unreadable.
    getBriefingStatus(controller.signal).then(body => {
      if (controller.signal.aborted) return;
      if (!isPromptStatus(body)) return setStatusFailure({ error: null });
      setStatus(body);
      setProvider(body.providers[0]?.provider);
    }, (error: unknown) => { if (!controller.signal.aborted) setStatusFailure({ error }); });
    return () => { controller.abort(); flight.current?.abort(); };
  }, []);

  if (statusFailure) return <p className="text-xs text-muted-foreground">{tp.statusFailed(copy.name, failureReason(statusFailure.error, tp))}</p>;
  if (!status?.available || !provider) return null;

  /** One request at a time, for the provider on screen, its body checked before anything reads it. */
  async function generate(chosen: Provider) {
    if (flight.current) return;
    const controller = new AbortController();
    flight.current = controller;
    setPending(true);
    setResult(undefined);
    setFailure(undefined);
    const settled = await requestBriefing(scope, chosen, controller.signal).then(body => ({ body }), (error: unknown) => ({ error }));
    if (controller.signal.aborted) return; // unmounted: the device filter changed, or the page was left
    flight.current = null;
    setPending(false);
    if ("error" in settled) setFailure({ error: settled.error });
    else if (isBriefing(settled.body)) setResult(settled.body);
    else setFailure({ error: null });
  }
  const who = (answer: Briefing) => `${providerLabel(answer.provider ?? "", t.ai.providerLabels)} · ${answer.model}`;
  const lead = (answer: Briefing) => answer.outcome === "selected" ? copy.selected(who(answer))
    : answer.reason === "unusable" ? copy.unusable(who(answer))
      : answer.reason === "error" ? copy.error(answer.error?.message ?? "") : copy.nothingToRank;

  return <section className="space-y-3 rounded-lg border bg-card p-4">
    <h2 className="font-semibold">{copy.title}</h2>
    <p className="text-sm text-muted-foreground">{copy.disclosure}</p>
    <div className="flex flex-wrap items-end gap-3">
      <div className="grid min-w-0 max-w-full gap-1 text-xs text-muted-foreground"><label htmlFor={pickerId}>{copy.provider}</label>
        <select id={pickerId} className="max-w-full rounded-md border border-input bg-background px-3 py-2 text-sm" value={provider} disabled={pending}
          onChange={e => { setProvider(e.target.value as Provider); setResult(undefined); setFailure(undefined); }}>
          {modelOptions(status.providers, t.ai.providerLabels).map(option => <option key={option.value} value={option.value}>{option.text}</option>)}
        </select></div>
      <Button variant="outline" disabled={pending} onClick={() => void generate(provider)}>{pending ? copy.pending : copy.generate}</Button>
    </div>
    {/* A refusal (409: the Fleet catalog flag, or main's AI gate) is the server's own sentence; any other failure is worded here. */}
    {failure && <p role="alert" className="text-sm text-destructive">
      {failure.error instanceof ApiError && failure.error.detail ? failure.error.detail : copy.failed(failureReason(failure.error, tp))}</p>}
    {result && <div aria-live="polite" className="space-y-1 text-sm"><p className="font-medium">{lead(result)}</p>
      <ul className="list-disc space-y-1 pl-5">{result.highlights.map(line => <li key={line.code}>{copy.codes[line.code](line.count)}</li>)}</ul>
    </div>}
  </section>;
}
