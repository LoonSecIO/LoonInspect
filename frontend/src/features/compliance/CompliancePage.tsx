import { Fragment, useEffect, useState } from "react";
import { useSearchParams } from "react-router";
import { Download } from "lucide-react";
import { Button } from "@/components/ui/button";
import { ApiError } from "@/config/api";
import { downloadEvidencePage, getEvidenceReport, sumFault, type EvidenceReport, type PartName, type ReportWindow, type Span, type Totals } from "@/features/compliance/api";
import { listConnections } from "@/features/mdm/api";
import type { MdmConnection } from "@/features/mdm/types";
import type { Translations } from "@/i18n/en";
import { useLocale } from "@/i18n/LocaleContext";

type Copy = Translations["compliance"];
const field = "h-9 rounded-md border border-input bg-background px-3 py-1 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring";
const stacked = "flex flex-col gap-1 text-xs text-muted-foreground";
/** To the minute, with its clock spelled out — the artefact's own reading of an instant. */
const when = (value: string) => `${value.slice(0, 16).replace("T", " ")} UTC`;

/**
 * The evidence report where an auditor can be sent (#536), rather than only as a download. It renders
 * #472's object and **computes nothing the object does not carry**: the *Read this first* sentences are
 * the server's own `readThisFirst` key rather than a second copy that would drift from the printed page,
 * and the only arithmetic is `sumFault`, a check on the identity the object asserts. **No framework is
 * named on it** — `compliance.test.ts` greps this page's dictionary for the four words the backend
 * refuses on the object. The picker offers the connections this account may read; which of them the
 * ledger has a heartbeat for is the endpoint's own answer, so the rest are refused at 409 and that
 * sentence is **shown where the report would be**, never swallowed.
 */
export function CompliancePage() {
  const { t } = useLocale();
  const copy = t.compliance;
  // The connection a Settings › Connections row sent us to, if it sent us. Read once and never written:
  // the picker is the control after that, and a connection this account cannot read is simply not in it.
  const [params] = useSearchParams();
  const sent = Number(params.get("connectionID")) || null;
  const [connections, setConnections] = useState<MdmConnection[] | null>(null);
  // A read that FAILED is not a tenant with no connections, and never reads as one (#150).
  const [listFailed, setListFailed] = useState(false);
  const [chosen, setChosen] = useState<number | "">("");
  const [dates, setDates] = useState<ReportWindow>({ start: "", asOf: "" });
  // What was asked for, which is what the effect answers. Set by a click, never by the effect itself (#15).
  const [asked, setAsked] = useState<{ id: number; dates: ReportWindow } | null>(null);
  const [report, setReport] = useState<EvidenceReport | null>(null);
  // The server's own sentence where it has one — no ledger (409), empty window (422), unreadable
  // catalogue (503) — else "": data, worded at render, so a language switch re-words it (#479).
  const [refused, setRefused] = useState<string | null>(null);
  const [downloadFailed, setDownloadFailed] = useState<string | null>(null);
  const asking = asked !== null && report === null && refused === null;

  function ask(id: number | "", window: ReportWindow) {
    setReport(null); setRefused(null); setDownloadFailed(null);
    if (id !== "") setAsked({ id, dates: window });
  }

  useEffect(() => {
    let cancelled = false;
    listConnections()
      .then((rows) => {
        if (cancelled) return;
        setConnections(rows);
        // The connection we were sent to, else the first, at the endpoint's default window: a page that
        // opened empty and waited for a click would be a step 3 on the way to what the reader came for.
        const first = rows.find((row) => row.id === sent) ?? rows[0];
        if (first) { setChosen(first.id); setAsked({ id: first.id, dates: { start: "", asOf: "" } }); }
      })
      .catch(() => void (cancelled || (setConnections([]), setListFailed(true))));
    return () => void (cancelled = true);
  }, [sent]);

  useEffect(() => {
    if (!asked) return;
    let cancelled = false;
    getEvidenceReport(asked.id, asked.dates)
      .then((answer) => void (cancelled || setReport(answer)))
      .catch((error: unknown) => void (cancelled || setRefused(error instanceof ApiError && error.detail ? error.detail : "")));
    return () => void (cancelled = true);
  }, [asked]);

  // What was ASKED for, not what the controls now read: the file an auditor keeps has to be the answer
  // they were looking at when they clicked, window and all — a date typed but not shown is not it yet.
  async function download() {
    if (!asked) return;
    setDownloadFailed(null);
    try {
      await downloadEvidencePage(asked.id, asked.dates);
    } catch (caught) {
      setDownloadFailed(caught instanceof Error ? caught.message : "");
    }
  }

  return (
    <section className="space-y-4">
      <h1 className="text-2xl font-semibold">{copy.title}</h1>
      <div className="flex flex-wrap items-end gap-3 rounded-lg border bg-card p-4">
        <label className={stacked}>{copy.connection}
          <select className={field} value={chosen} disabled={!connections?.length}
            onChange={(event) => { const id = event.target.value ? Number(event.target.value) : ""; setChosen(id); ask(id, dates); }}>
            {connections?.map((connection) => <option key={connection.id} value={connection.id}>{connection.name}</option>)}
          </select>
        </label>
        <label className={stacked}>{copy.start}
          <input type="date" className={field} value={dates.start} onChange={(event) => setDates({ ...dates, start: event.target.value })} />
        </label>
        <label className={stacked}>{copy.asOf}
          <input type="date" className={field} value={dates.asOf} onChange={(event) => setDates({ ...dates, asOf: event.target.value })} />
        </label>
        <Button variant="outline" size="sm" disabled={chosen === ""} onClick={() => ask(chosen, dates)}>{copy.show}</Button>
        <Button variant="outline" size="sm" disabled={!asked} onClick={download}>
          <Download className="mr-1 h-3 w-3" />{copy.download}
        </Button>
        <p className="w-full text-xs text-muted-foreground">{copy.windowHint}</p>
      </div>
      {listFailed && <p className="text-sm text-destructive">{copy.connectionsFailed}</p>}
      {connections?.length === 0 && !listFailed && <p className="text-sm">{copy.noConnections}</p>}
      {downloadFailed !== null && <p className="text-sm text-destructive">{downloadFailed || copy.failed}</p>}
      {refused !== null && <p className="text-sm text-destructive">{refused || copy.failed}</p>}
      {asking && <p className="text-sm text-muted-foreground">{copy.asking}</p>}
      {report && <Rendered report={report} copy={copy} />}
    </section>
  );
}

/** The object, drawn. Split out so the page above is the picker and the window and nothing else. */
function Rendered({ report, copy }: { report: EvidenceReport; copy: Copy }) {
  const { header, totals } = report;
  const { method } = header;
  const fault = sumFault(totals.fleet);
  const titles = new Map(report.rules.map((rule) => [rule.ruleID, rule.title]));
  const names = new Map(report.devices.map((device) => [device.deviceID, device.name || device.deviceID]));
  // Never "0 days": a zero meaning *seen once* must not wear the costume of a zero meaning *never happened*.
  const said = (span: Span) => (span.days ? copy.days(span.days) : copy.underOne);
  const parts = (total: Totals) =>
    Object.entries(total.notObservedParts ?? {}).map(([name, span]) => `${copy.parts[name as PartName]}: ${said(span)}`).join(" · ") || "—";
  const pairs: [string, string][] = [
    [copy.headConnection, `${method.connection.name} — ${method.connection.provider}, #${method.connection.connectionID}`],
    [copy.headSource, method.source],
    [copy.headWindow, `${when(method.window.start)} → ${when(method.window.asOf)}`],
    [copy.headCatalogue, copy.catalogueAt(method.catalogue.version, method.catalogue.rules)],
    [copy.headContract, header.contractVersions.join(", ") || "—"],
    [copy.headClock, header.clock.statement],
    [copy.headNotVisible, `${header.notVisible.controls.join(", ")} — ${header.notVisible.statement}`]
  ];
  // The fleet is the first row of the first table, drawn whether or not its sum closed: the fault line
  // is about these figures, and a reader sent to report them has to be able to read them.
  const fleet: [string, Totals][] = totals.fleet.window ? [[copy.fleet, totals.fleet as Totals]] : [];
  const table = (heading: string, first: string, rows: [string, Totals][]) => (
    <div className="space-y-1">
      <h2 className="text-xs font-medium uppercase tracking-wide text-muted-foreground">{heading}</h2>
      <div className="overflow-x-auto rounded-lg border bg-card">
        <table className="w-full text-sm">
          <thead className="border-b bg-muted/30 text-left text-muted-foreground">
            <tr>{[first, copy.colMet, copy.colUnmet, copy.colNotObserved, copy.colOfWhich, copy.colTotal].map((label) => <th key={label} className="px-3 py-2 font-medium">{label}</th>)}</tr>
          </thead>
          <tbody>
            {rows.map(([label, total]) => (
              <tr key={label} className="border-b align-top last:border-0">
                <td className="px-3 py-2">{label}</td>
                {(["met", "unmet", "notObserved"] as const).map((state) => <td key={state} className="px-3 py-2 tabular-nums">{said(total[state])}</td>)}
                <td className="px-3 py-2 text-xs text-muted-foreground">{parts(total)}</td>
                <td className="px-3 py-2 tabular-nums">{said(total.window)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );

  return (
    <div className="space-y-4">
      <div className="space-y-2 rounded-lg border bg-card p-4">
        <p className="text-sm">{method.statement}</p>
        <dl className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1 text-sm">
          {pairs.map(([label, value]) => (
            <Fragment key={label}><dt className="text-muted-foreground">{label}</dt><dd>{value}</dd></Fragment>
          ))}
        </dl>
        <p className="border-l-2 border-foreground pl-3 text-sm font-medium">{header.refusal}</p>
      </div>
      {report.readThisFirst.map((sentence) => (
        <div key={sentence} className="rounded-lg border border-foreground/30 p-3 text-sm">
          <b className="block">{copy.readThisFirst}</b>{sentence}
        </div>
      ))}
      <p className="text-sm text-muted-foreground">{copy.sumSaid}</p>
      {/* A sum that does not close is printed, never hidden (docs/troubleshooting.md §17 step 9). */}
      {fault && <p className="text-sm text-destructive">{copy.sumFault(fault.sum, fault.window)}</p>}
      {table(copy.byRule, copy.colRule, [...fleet, ...Object.entries(totals.byRule).map(([id, total]): [string, Totals] => [`${id} — ${titles.get(id) ?? id}`, total])])}
      {table(copy.byDevice, copy.colMac, Object.entries(totals.byDevice).map(([id, total]): [string, Totals] => [names.get(id) ?? id, total]))}
    </div>
  );
}
