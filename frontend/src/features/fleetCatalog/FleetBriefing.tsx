import { useEffect, useRef, useState } from "react";
import { Button } from "@/components/ui/button";
import { apiRequest, ApiError } from "@/config/api";
import { useLocale } from "@/i18n/LocaleContext";

type Status = { available: boolean; reason: string | null; providers: { provider: string; model: string }[] };
type Briefing = { outcome: "selected" | "fallback"; highlights: {code: string; count: number; text: string}[]; provider: string | null; model: string | null; detail: string | null };
const words = {
  en: { title: "Migration briefing", generate: "Generate briefing", loading: "Preparing briefing…", source: "Model", fallback: "Local summary", aggregate: "Only summary counts for this inventory scope are sent to the configured provider.", error: "The briefing could not be read. Check AI settings and try again." },
  de: { title: "Migrationsübersicht", generate: "Übersicht erstellen", loading: "Übersicht wird erstellt…", source: "Modell", fallback: "Lokale Zusammenfassung", aggregate: "Nur zusammengefasste Zahlen zur Inventarauswahl werden an den konfigurierten Anbieter gesendet.", error: "Die Übersicht konnte nicht geladen werden. KI-Einstellungen prüfen und erneut versuchen." }
};

export function FleetBriefing({ scope }: {scope: string}) {
  const { locale } = useLocale();
  const copy = words[locale];
  const [status, setStatus] = useState<Status>();
  const [provider, setProvider] = useState("");
  const [result, setResult] = useState<Briefing>();
  const [error, setError] = useState("");
  const [pending, setPending] = useState(false);
  const flight = useRef<AbortController | null>(null);
  useEffect(() => {
    const controller = new AbortController();
    apiRequest<Status>("/fleet-catalog/briefing", {signal: controller.signal}).then(s => {
      if (!controller.signal.aborted) setStatus(s);
    }).catch(() => {});
    return () => { controller.abort(); flight.current?.abort(); };
  }, []);
  if (!status?.available) return null;
  const selectedProvider = provider || status.providers[0]?.provider;
  async function generate() {
    if (flight.current || !selectedProvider) return;
    const controller = new AbortController();
    flight.current = controller;
    setError("");
    setResult(undefined);
    setPending(true);
    try {
      const data = await apiRequest<Briefing>("/fleet-catalog/briefing?" + scope, {method: "POST", json: {provider: selectedProvider}, signal: controller.signal});
      if (!controller.signal.aborted) setResult(data);
    } catch (e) {
      if (!controller.signal.aborted) setError(e instanceof ApiError && e.detail ? e.detail : copy.error);
    } finally {
      flight.current = null;
      if (!controller.signal.aborted) setPending(false);
    }
  }
  return <section className="space-y-2 rounded-lg border bg-card p-4">
    <h2 className="font-semibold">{copy.title}</h2><p className="text-sm text-muted-foreground">{copy.aggregate}</p>
    <label className="block text-sm">{locale === "de" ? "Anbieter und Modell" : "Provider and model"}
      <select className="ml-2 rounded-md border bg-background p-2" disabled={pending}
        value={selectedProvider ?? ""} onChange={event => { setProvider(event.target.value); setResult(undefined); setError(""); }}>
        {status.providers.map(p => <option key={p.provider} value={p.provider}>{p.provider} · {p.model}</option>)}
      </select>
    </label>
    <Button variant="outline" onClick={() => void generate()} disabled={pending || !selectedProvider}>{pending ? copy.loading : copy.generate}</Button>
    {error && <p role="alert" className="text-sm text-destructive">{error}</p>}
    {result && <div aria-live="polite" className="space-y-2">
      <p className="text-xs font-medium text-muted-foreground">{result.outcome === "fallback" ? copy.fallback : [copy.source, result.provider, result.model].filter(Boolean).join(" · ")}</p>
      {result.detail && <p className="text-sm">{result.detail}</p>}
      <ul className="list-disc space-y-1 pl-5 text-sm">{result.highlights.map(h => <li key={h.code}>{h.text}</li>)}</ul>
    </div>}
  </section>;
}
