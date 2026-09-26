import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { ApiError } from "@/config/api";
import { listSubmissions, type SubmissionCaseOut } from "@/features/submissions/api";
import { act, asksStatus, refreshWait, replaceCase } from "@/features/submissions/cases";
import type { Translations } from "@/i18n/en";
import { useLocale, type Locale } from "@/i18n/LocaleContext";

/** What the list read answered. A failed read keeps the server's sentence, if one came. */
export type CasesRead =
  | { state: "loading" }
  | { state: "failed"; said: string | null }
  | { state: "ready"; enabled: boolean; cases: SubmissionCaseOut[] };
/** One case's act in flight, its withdrawal question open, or the refusal its last act got. */
export type RowAct = { busy?: boolean; confirming?: boolean; error?: string };
type Handlers = Record<"refresh" | "ask" | "withdraw" | "cancel", (id: string) => void>;

interface ViewProps {
  read: CasesRead;
  copy: Translations["submissionCases"];
  locale: Locale;
  now: number;
  acts?: Record<string, RowAct>;
  on?: Partial<Handlers>;
}

/** This organization's cases for one read and the acts in flight; stateless, so the node lane renders it. */
export function SubmissionCasesView({ read, copy, locale, now, acts = {}, on = {} }: ViewProps) {
  const when = (at: string) => new Date(at).toLocaleString(locale, { dateStyle: "medium", timeStyle: "short" });
  return (
    <section className="space-y-3 rounded-md border p-4" aria-label={copy.title}>
      <h2 className="font-semibold">{copy.title}</h2>
      <p className="text-sm text-muted-foreground">{copy.description}</p>
      {read.state === "loading" && <p className="text-sm text-muted-foreground">{copy.loading}</p>}
      {read.state === "failed" && <p role="alert" className="text-sm text-destructive">{read.said ?? copy.loadFailed}</p>}
      {read.state === "ready" && !read.enabled && <p className="text-sm">{copy.notEnabled}</p>}
      {read.state === "ready" && read.cases.length === 0 && <p className="text-sm text-muted-foreground">{copy.empty}</p>}
      {read.state === "ready" && read.cases.length > 0 && (
        <ul className="divide-y">
          {read.cases.map((item) => {
            const row = acts[item.id] ?? {};
            const wait = refreshWait(item, now);
            const lead = item.state === "needs_information" ? copy.question : item.state === "declined" ? copy.reason : copy.note;
            return (
              <li key={item.id} className="space-y-1 py-3 text-sm">
                <p className="break-all">
                  <span className="font-medium">{item.appName}</span> {item.versions.join(" · ")}
                  {item.bundleId && <span className="block font-mono text-xs text-muted-foreground">{item.bundleId}</span>}
                </p>
                <p className="text-muted-foreground">
                  {[copy.kinds[item.kind], item.finding, copy.created(when(item.createdAt))].filter(Boolean).join(" · ")}
                </p>
                <p className="font-medium">{copy.states[item.state as keyof typeof copy.states] ?? item.state}</p>
                {/* `accepted` is not covered: only `published` names the release, and what it covers. */}
                {item.state === "published" && (
                  <p className="break-all">
                    {copy.release} <code>{item.release}</code>
                    {item.coverage && <span className="block">{`${copy.coverage} ${item.coverage}`}</span>}
                  </p>
                )}
                {item.note && <p>{`${lead} ${item.note}`}</p>}
                {item.lastError && <p className="text-destructive">{item.lastError}</p>}
                {item.withdrawnAt && item.state !== "withdrawn" && <p>{copy.unconfirmed(when(item.withdrawnAt))}</p>}
                <div className="flex flex-wrap gap-2">
                  {asksStatus(item) && (
                    <Button size="sm" variant="outline" disabled={row.busy || wait > 0} onClick={() => on.refresh?.(item.id)}>
                      {wait > 0 ? copy.refreshIn(wait) : copy.refresh}
                    </Button>
                  )}
                  {item.state !== "withdrawn" && !row.confirming && (
                    <Button size="sm" variant="outline" disabled={row.busy} onClick={() => on.ask?.(item.id)}>{copy.withdraw}</Button>
                  )}
                </div>
                {row.confirming && (
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-xs text-muted-foreground">{copy.withdrawConfirm}</span>
                    <Button size="sm" variant="destructive" disabled={row.busy} onClick={() => on.withdraw?.(item.id)}>{copy.confirm}</Button>
                    <Button size="sm" variant="ghost" disabled={row.busy} onClick={() => on.cancel?.(item.id)}>{copy.cancel}</Button>
                  </div>
                )}
                {row.error && <p role="alert" className="text-destructive">{row.error}</p>}
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}

/**
 * Settings › Intelligence Access: this organization's coverage requests and match reports (#623). Every
 * submissions route needs SYSTEM_WRITE, so the page renders this for administrators only, beside the paid
 * panel and never inside it: the list, Refresh and Withdraw stay open while INTELLIGENCE_ACCESS is off, so
 * the switch never strands a withdrawal.
 */
export function SubmissionCases() {
  const { t, locale } = useLocale();
  const copy = t.submissionCases;
  const [read, setRead] = useState<CasesRead>({ state: "loading" });
  const [acts, setActs] = useState<Record<string, RowAct>>({});
  const [now, setNow] = useState(() => Date.now());

  useEffect(() => {
    let live = true;
    listSubmissions()
      .then(({ enabled, cases }) => {
        if (!live) return;
        setRead({ state: "ready", enabled, cases });
        setNow(Date.now());
      })
      .catch((caught: unknown) => {
        if (live) setRead({ state: "failed", said: caught instanceof ApiError ? caught.detail : null });
      });
    return () => {
      live = false;
    };
  }, []);

  // A one-second clock only while some Refresh waits, so its remaining wait counts down.
  const waiting = read.state === "ready" && read.cases.some((item) => asksStatus(item) && refreshWait(item, now) > 0);
  useEffect(() => {
    if (!waiting) return;
    const handle = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(handle);
  }, [waiting]);

  const mark = (id: string, row: RowAct) => setActs((all) => ({ ...all, [id]: row }));
  function run(id: string, kind: "status" | "withdraw") {
    mark(id, { busy: true });
    void act(kind, id, copy.failed).then((outcome) => {
      if (outcome === null) return; // that case's act is already in flight
      if ("error" in outcome) return mark(id, { error: outcome.error });
      mark(id, {});
      setNow(Date.now());
      setRead((current) => (current.state === "ready" ? { ...current, cases: replaceCase(current.cases, outcome.item) } : current));
    });
  }
  const on: Handlers = {
    refresh: (id) => run(id, "status"),
    ask: (id) => mark(id, { confirming: true }),
    withdraw: (id) => run(id, "withdraw"),
    cancel: (id) => mark(id, {})
  };
  return <SubmissionCasesView {...{ read, copy, locale, now, acts, on }} />;
}
