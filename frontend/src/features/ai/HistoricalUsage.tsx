import { useEffect, useState } from "react";
import { useLocale } from "@/i18n/LocaleContext";
import { apiRequest } from "@/config/api";

type Calls = {
  feature: string;
  provider: string;
  requested: string;
  reported: string;
  outcome: string;
  events: number;
  request_ms: number;
  input_tokens: number;
  input_reports: number;
  output_tokens: number;
  output_reports: number;
  cached_tokens: number;
  cache_reports: number;
  provider_ms: number;
  provider_reports: number;
};
type Queue = {
  day: string;
  provider: string;
  outcome: string;
  events: number;
  queue_wait_ms: number;
  max_queue_wait_ms: number;
};
type Report = {
  firstMeasured: string | null;
  retentionDays: number;
  calls: Calls[];
  queue: Queue[];
  pending: number;
  oldestPendingSeconds: number | null;
};
function isoDay(offset: number) {
  const d = new Date();
  d.setUTCDate(d.getUTCDate() + offset);
  return d.toISOString().slice(0, 10);
}
export function HistoricalUsage() {
  const de = useLocale().locale === "de",
    unknown = de ? "Unbekannt" : "Unknown";
  const [start, setStart] = useState(isoDay(-29)),
    [end, setEnd] = useState(isoDay(0));
  const [report, setReport] = useState<Report>(),
    [error, setError] = useState("");
  useEffect(() => {
    let live = true;
    if (start && end)
      apiRequest<Report>(
        "/system/ai/usage?" + new URLSearchParams({ start, end }),
      )
        .then((r) => {
          if (live) {
            setReport(r);
            setError("");
          }
        })
        .catch((e) => {
          if (live) {
            setError(String(e));
            setReport(undefined);
          }
        });
    return () => {
      live = false;
    };
  }, [start, end]);
  const measured = (value: number, n: number, total: number) =>
    n ? value.toLocaleString() + " (" + n + "/" + total + ")" : unknown;
  return (
    <section className="space-y-3 rounded-lg border p-4">
      <h2 className="text-lg font-semibold">
        {de
          ? "KI-Nutzung und Verarbeitung"
          : "AI usage and processing capacity"}
      </h2>
      <div className="flex gap-4">
        <label>
          {de ? "Von (UTC)" : "From (UTC)"}{" "}
          <input
            type="date"
            value={start}
            max={end}
            onChange={(e) => setStart(e.target.value)}
          />
        </label>
        <label>
          {de ? "Bis" : "Through"}{" "}
          <input
            type="date"
            value={end}
            min={start}
            max={isoDay(0)}
            onChange={(e) => setEnd(e.target.value)}
          />
        </label>
      </div>
      {error && <p role="alert">{error}</p>}
      {report && (
        <>
          <p>
            {de ? "Erste erhaltene Messung" : "First retained measurement"} ·{" "}
            {report.firstMeasured || "—"} · {report.retentionDays}{" "}
            {de ? "Tage Aufbewahrung" : "days retained"}
          </p>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr>
                  {(de
                    ? [
                        "Funktion / Anbieter",
                        "Angefordert → gemeldet",
                        "Ergebnis",
                        "Aufrufe",
                        "Anfrage (ms)",
                        "Eingabe",
                        "Ausgabe",
                        "Cache-Token",
                        "Anbieter (ms)",
                      ]
                    : [
                        "Feature / provider",
                        "Requested → reported model",
                        "Outcome",
                        "Calls",
                        "Request ms",
                        "Input tokens",
                        "Output tokens",
                        "Cached tokens",
                        "Provider ms",
                      ]
                  ).map((h) => (
                    <th key={h}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {report.calls.map((c) => (
                  <tr
                    key={JSON.stringify([
                      c.feature,
                      c.provider,
                      c.requested,
                      c.reported,
                      c.outcome,
                    ])}
                  >
                    <td>
                      {c.feature} · {c.provider}
                    </td>
                    <td>
                      {c.requested || unknown} → {c.reported || unknown}
                    </td>
                    <td>{c.outcome}</td>
                    <td>{c.events}</td>
                    <td>{c.request_ms}</td>
                    <td>
                      {measured(c.input_tokens, c.input_reports, c.events)}
                    </td>
                    <td>
                      {measured(c.output_tokens, c.output_reports, c.events)}
                    </td>
                    <td>
                      {measured(c.cached_tokens, c.cache_reports, c.events)}
                    </td>
                    <td>
                      {measured(c.provider_ms, c.provider_reports, c.events)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {!report.calls.length && (
            <p>
              {de
                ? "Keine gemessenen Aufrufe im Zeitraum."
                : "No measured calls in this range."}
            </p>
          )}
          <p>
            {de
              ? "Berichtsabdeckung in Klammern. Aktuell ausstehend"
              : "Reporting calls / total calls in parentheses. Pending now"}{" "}
            · {report.pending} ·{" "}
            {de ? "Ältester Auftrag" : "Oldest pending job"} ·{" "}
            {report.oldestPendingSeconds === null
              ? "—"
              : Math.floor(report.oldestPendingSeconds) + " s"}
          </p>
          <table className="w-full text-left text-sm">
            <thead>
              <tr>
                {(de
                  ? [
                      "UTC",
                      "Anbieter",
                      "Auftragsereignis",
                      "Anzahl",
                      "Max. Wartezeit (s)",
                    ]
                  : [
                      "UTC day",
                      "Provider",
                      "Queue event",
                      "Count",
                      "Maximum queue age at attempt (s)",
                    ]
                ).map((h) => (
                  <th key={h}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {report.queue.map((q) => (
                <tr key={[q.day, q.provider, q.outcome].join("/")}>
                  <td>{q.day}</td>
                  <td>{q.provider}</td>
                  <td>{q.outcome}</td>
                  <td>{q.events}</td>
                  <td>
                    {["started", "retry"].includes(q.outcome)
                      ? Math.round(q.max_queue_wait_ms / 1000)
                      : "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </section>
  );
}
