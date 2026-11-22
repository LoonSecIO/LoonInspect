import { useEffect, useState } from "react";
import { Link } from "react-router";
import { apiRequest } from "@/config/api";
import { useLocale } from "@/i18n/LocaleContext";
import { RunLogPanel } from "./RunLogPanel";

type Poll = {
  id: string;
  start: string;
  end: string;
  complete: boolean;
  selected: number;
  requests?: number;
  effectiveSelector?: string;
};
type Change = {
  change_id: number | null;
  field: string | null;
  entry_label: string | null;
  change: string | null;
  id: string;
  device: number | null;
  hostname: string | null;
  subject_id: string;
  section: string;
  status: string;
  poll: string | null;
  discovered: string;
  report_at: string | null;
  delaySeconds: number | null;
  build: string | null;
  old_build: string | null;
};
type Report = {
  complete: boolean;
  affectedMacs: number;
  counts: Record<string, number>;
  polls: Poll[];
  rows: Change[];
  total: number;
  gaps: [string, string][];
};
export function DailyCoverage({ jobId }: { jobId: string }) {
  const de = useLocale().locale === "de";
  const [open, setOpen] = useState(false),
    [page, setPage] = useState(0),
    [log, setLog] = useState("");
  const [report, setReport] = useState<Report>(),
    [error, setError] = useState("");
  useEffect(() => {
    if (!open) return;
    let active = true;
    apiRequest<Report>("/runs/" + jobId + "/coverage?page=" + page)
      .then((v) => {
        if (active) {
          setReport(v);
          setError("");
        }
      })
      .catch((e) => {
        if (active) setError(String(e));
      });
    return () => {
      active = false;
    };
  }, [jobId, page, open]);
  const states: Record<string, string> = de
    ? {
        coveredMiss: "Erst im Vollabruf",
        baseline: "Ersterfassung",
        failedWindow: "Fehlgeschlagenes Zeitfenster",
        uncovered: "Ohne Zeitfenster",
        afterLastWindow: "Nach letztem Zeitfenster",
        incomparableScope: "Anderer Umfang",
        missingReportTime: "Inventarzeit fehlt",
      }
    : {
        coveredMiss: "First seen by crawl despite coverage",
        baseline: "First observation",
        failedWindow: "Failed window",
        uncovered: "No covering window",
        afterLastWindow: "After last poll",
        incomparableScope: "Different scope",
        missingReportTime: "Missing inventory report time",
      };
  return (
    <div>
      <button className="underline" onClick={() => setOpen(!open)}>
        {de ? "Tagesabdeckung" : "Daily coverage"}
      </button>
      {open && (
        <div className="space-y-2 p-2">
          {error ||
            (!report ? (
              "…"
            ) : !report.complete ? (
              de ? (
                "Vergleich unvollständig"
              ) : (
                "Comparison incomplete"
              )
            ) : (
              <>
                <p>
                  {report.counts.coveredMiss || 0} {states.coveredMiss} ·{" "}
                  {report.affectedMacs} Macs
                </p>
                <p>
                  {Object.entries(report.counts)
                    .map(([s, n]) => states[s] + " (" + n + ")")
                    .join(" · ")}
                </p>
                <details>
                  <summary>
                    {de ? "Zeitfenster" : "Poll windows"} ({report.polls.length}
                    )
                  </summary>
                  {report.polls.map((p) => (
                    <p key={p.id}>
                      <button
                        className="underline"
                        onClick={() => setLog(p.id)}
                      >
                        {p.start} → {p.end}
                      </button>{" "}
                      · {p.complete ? "✓" : "×"} · {p.selected} Macs ·{" "}
                      {p.requests ?? "?"} HTTP · {p.effectiveSelector}
                    </p>
                  ))}
                  {report.gaps.map(([start, end]) => (
                    <p key={start}>
                      {states.uncovered} · {start} → {end}
                    </p>
                  ))}
                </details>
                {report.rows.map((c) => (
                  <p key={c.change_id ?? c.id + c.section}>
                    {c.device ? (
                      <Link to={"/devices/" + c.device}>
                        {c.hostname || c.subject_id}
                      </Link>
                    ) : (
                      c.subject_id
                    )}{" "}
                    · {states[c.status]} · {c.section} {c.field || c.entry_label} {c.change} {c.old_build}{" "}
                    {c.build && "→ " + c.build} · {c.report_at || "?"} →{" "}
                    {c.discovered} ({c.delaySeconds ?? "?"} s){" "}
                    {c.poll && (
                      <button
                        className="underline"
                        onClick={() => setLog(c.poll!)}
                      >
                        {de ? "Abruf öffnen" : "Open poll"}
                      </button>
                    )}
                  </p>
                ))}
                {report.total > 100 && (
                  <>
                    <button disabled={!page} onClick={() => setPage(page - 1)}>
                      ←
                    </button>{" "}
                    {page + 1}{" "}
                    <button
                      disabled={(page + 1) * 100 >= report.total}
                      onClick={() => setPage(page + 1)}
                    >
                      →
                    </button>
                  </>
                )}
              </>
            ))}
          <button className="underline" onClick={() => setLog(jobId)}>
            {de ? "Vollabruf öffnen" : "Open full crawl"}
          </button>
          {log && <RunLogPanel key={log} jobId={log} joined={false} />}
        </div>
      )}
    </div>
  );
}
