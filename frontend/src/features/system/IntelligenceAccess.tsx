import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { apiRequest, ApiError } from "@/config/api";
import { useLocale } from "@/i18n/LocaleContext";

interface Access {
  enabled: boolean;
  credentialPresent: boolean;
  state: string;
  updatesUntil: string | null;
  lastAttemptAt: string | null;
  lastRefreshAt: string | null;
  sourceAsOf: string | null;
  selectedCorpus: string | null;
  error: string | null;
}

export function IntelligenceAccess({ canWrite }: { canWrite: boolean }) {
  const { t } = useLocale();
  const copy = t.intelligence;
  const [access, setAccess] = useState<Access | null>(null);
  const [secret, setSecret] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    let active = true;
    apiRequest<Access>("/system/intelligence").then((value) => {
      if (active) setAccess(value);
    }).catch(() => { if (active) setError(copy.loadFailed); });
    return () => { active = false; };
  }, [copy.loadFailed]);

  async function perform(action: "activate" | "rotate" | "refresh" | "disconnect") {
    setBusy(true);
    setError(null);
    const activation = secret;
    setSecret("");
    try {
      setAccess(await apiRequest<Access>(`/system/intelligence/${action}`, {
        method: "POST", ...(action === "activate" ? { json: { secret: activation } } : {})
      }));
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.detail ?? copy.failed : copy.failed);
    } finally {
      setBusy(false);
    }
  }
  // A failed read is visible. A disabled preview adds no product control: its page says
  // why in one sentence rather than drawing an empty panel (#622).
  if (!access) return error ? <p role="alert">{error}</p> : null;
  if (!access.enabled) return <p className="text-sm text-muted-foreground">{copy.notEnabled}</p>;
  const displayTime = (value: string | null) => value ? new Date(value).toLocaleString() : copy.none;
  const state = copy.states[access.state as keyof typeof copy.states] ?? copy.states.unknown;
  return <section className="space-y-3 rounded-md border p-4" aria-label={copy.paidTitle}>
    <h2 className="font-semibold">{copy.paidTitle}</h2>
    <p className="text-sm text-muted-foreground">{copy.description}</p>
    <dl className="grid grid-cols-2 gap-2 text-sm">
      <dt>{copy.state}</dt><dd>{state}</dd>
      <dt>{copy.credential}</dt><dd>{access.credentialPresent ? copy.present : copy.none}</dd>
      <dt>{copy.until}</dt><dd>{displayTime(access.updatesUntil)}</dd>
      <dt>{copy.attempt}</dt><dd>{displayTime(access.lastAttemptAt)}</dd>
      <dt>{copy.refresh}</dt><dd>{displayTime(access.lastRefreshAt)}</dd>
      <dt>{copy.source}</dt><dd>{displayTime(access.sourceAsOf)}</dd>
      <dt>{copy.selected}</dt><dd className="break-all">{access.selectedCorpus ?? copy.none}</dd>
    </dl>
    <p className="text-sm text-muted-foreground">{copy.freshness}</p>
    <p className="text-sm text-muted-foreground">{copy.disclosure}</p>
    {(error || access.error) && <p role="alert" className="text-sm text-destructive">{error || access.error}</p>}
    {canWrite && <>
      <label className="block text-sm" htmlFor="intelligence-activation">{copy.activation}</label>
      <input id="intelligence-activation" type="password" autoComplete="off" value={secret}
        onChange={(event) => setSecret(event.target.value)} disabled={busy}
        className="w-full rounded-md border bg-background px-3 py-2" />
      <div className="flex flex-wrap gap-2">
        <Button disabled={busy || !secret} onClick={() => void perform("activate")}>{copy.activate}</Button>
        <Button variant="outline" disabled={busy || !access.credentialPresent}
          onClick={() => void perform("refresh")}>{copy.refreshNow}</Button>
        <Button variant="outline" disabled={busy || !access.credentialPresent}
          onClick={() => void perform("rotate")}>{copy.rotate}</Button>
        <Button variant="outline" disabled={busy || !access.credentialPresent}
          onClick={() => void perform("disconnect")}>{copy.disconnect}</Button>
      </div>
      <p className="text-xs text-muted-foreground">{copy.recovery}</p>
    </>}
  </section>;
}
