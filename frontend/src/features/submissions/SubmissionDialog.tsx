import { useReducer, useState, type ChangeEvent, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { Link } from "react-router";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import type { CatalogEntry } from "@/features/catalog/types";
import { askPreview, askSend, bodyOf, canSend, correctionFor, coverageFor, dialog, HTTPS, OPENED, oneAtATime, TEXT_LIMIT, type Dialog, type Move, type Named, type Typed } from "@/features/submissions/dialog";
import type { Translations } from "@/i18n/en";

type Copy = Translations["submissions"];
type ViewProps = { named: Named; findings?: string[]; state: Dialog; copy: Copy; dispatch: (move: Move) => void; onPreview: () => void; onSend: () => void; onClose: () => void };

const Box = ({ on, disabled, onChange, children }: { on: boolean; disabled: boolean; onChange: (on: boolean) => void; children: ReactNode }) => (
  <label className="flex items-start gap-2 text-sm"><input type="checkbox" className="mt-1" checked={on} disabled={disabled}
    onChange={(event) => onChange(event.target.checked)} /><span>{children}</span></label>);

/** Request coverage or Report an incorrect match (#623), stateless so the node lane renders it. The payload is
 *  the preview's own answer printed as it came, never rebuilt here; the fields lock once Send has answered. */
export function SubmissionView({ named, findings = [], state, copy, dispatch, onPreview, onSend, onClose }: ViewProps) {
  const { typed, shown, sent, busy } = state;
  const body = bodyOf(named, typed);
  const badUrl = !!body.publicUrl && !HTTPS.test(body.publicUrl);
  const locked = busy || sent !== null;
  const field = (name: keyof Typed) => ({ value: typed[name], disabled: locked, "aria-describedby": "submission-guidance",
    onChange: (event: ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => dispatch({ type: "typed", field: name, value: event.target.value }) });
  const tick = (box: "permission" | "override") => (on: boolean) => dispatch({ type: "ticked", box, on });
  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/50 p-4" onKeyDown={(event) => event.key === "Escape" && onClose()}>
      <div role="dialog" aria-modal="true" aria-labelledby="submission-title" className="w-full max-w-2xl space-y-4 rounded-lg border bg-background p-6 shadow-lg">
        <h2 id="submission-title" className="text-lg font-semibold">{copy.title[named.kind]}</h2>
        <p className="text-sm">{named.appName} {named.versions.join(" · ")}<span className="block font-mono text-xs text-muted-foreground">{named.bundleId}</span></p>
        {/* A correction names one finding, picked from the row's ids alone; a pick is an edit, so it drops the preview. */}
        {named.kind === "correction" && (findings.length > 1
          ? <label className="block space-y-1 text-sm"><span>{copy.findingLabel}</span>
            <select className="block w-full rounded-md border border-input bg-background px-3 py-2 font-mono disabled:opacity-50" value={body.finding ?? ""}
              disabled={locked} onChange={(event) => dispatch({ type: "typed", field: "finding", value: event.target.value })}>
              {findings.map((id) => <option key={id}>{id}</option>)}</select></label>
          : <p className="text-sm">{copy.findingLabel}<span className="block font-mono">{body.finding}</span></p>)}
        <label className="block space-y-1 text-sm"><span>{copy.urlLabel}</span><Input type="url" placeholder="https://" maxLength={512} autoFocus {...field("publicUrl")} /></label>
        {badUrl && <p className="text-sm text-destructive">{copy.urlHttps}</p>}
        <label className="block space-y-1 text-sm"><span>{copy.textLabel}</span>
          <textarea className="block min-h-24 w-full rounded-md border border-input bg-background px-3 py-2 disabled:opacity-50" maxLength={TEXT_LIMIT} {...field("text")} /></label>
        <p className="text-right text-xs text-muted-foreground">{copy.counter(typed.text.length, TEXT_LIMIT)}</p>
        <label className="block space-y-1 text-sm"><span>{copy.contactLabel}</span><Input maxLength={256} {...field("contact")} /></label>
        <p id="submission-guidance" className="text-sm text-muted-foreground">{copy.guidance}</p>
        <Button variant="outline" size="sm" disabled={locked || badUrl} onClick={onPreview}>{copy.preview}</Button>
        {shown === null ? <p className="text-sm text-muted-foreground">{copy.previewFirst}</p> : <>
          <pre className="max-h-64 overflow-auto rounded-md bg-muted p-3 font-mono text-xs">{JSON.stringify(shown.answer.payload, null, 2)}</pre>
          <p className="text-xs text-muted-foreground">{copy.caseKey}</p></>}
        {shown?.answer.excludedBy && <>
          <p className="text-sm">{copy.excluded(named.bundleId ?? "", shown.answer.excludedBy)}</p>
          <Box on={state.override} disabled={locked} onChange={tick("override")}>{copy.override}</Box></>}
        <Box on={state.permission} disabled={locked || shown === null} onChange={tick("permission")}>{copy.permission}</Box>
        {state.error && <p role="alert" className="text-sm text-destructive">{state.error}</p>}
        {sent && <div role="status" className="space-y-1 text-sm">
          <p className="font-medium">{copy.state(sent.state)}</p>
          {sent.lastError && <p className="text-destructive">{sent.lastError}</p>}
          <Link to="/settings/intelligence-access" className="underline underline-offset-4">{copy.follow}</Link></div>}
        <div className="flex justify-end gap-2">
          <Button variant="outline" onClick={onClose}>{copy.close}</Button>
          {(sent?.state ?? "pending") === "pending" && <Button disabled={!canSend(state, body)} onClick={onSend}>{copy.send}</Button>}
        </div>
      </div>
    </div>
  );
}

/** The dialog over the page, for either kind: Report an incorrect match opens it with its finding and release. */
export function SubmissionDialog({ named, findings, copy, onClose }: { named: Named; findings?: string[]; copy: Copy; onClose: () => void }) {
  const [state, dispatch] = useReducer(dialog, OPENED);
  const [run] = useState(() => oneAtATime(dispatch));
  const { shown } = state;
  return createPortal(
    <SubmissionView named={named} findings={findings} state={state} copy={copy} dispatch={dispatch} onClose={onClose}
      onPreview={() => void run(() => askPreview(bodyOf(named, state.typed), copy.failed))}
      onSend={() => shown && void run(() => askSend(shown, state.override, copy.failed))} />,
    document.body
  );
}

/** Request coverage under an `unknown_app` build (#623): beside the cell's three states, never one of them. */
export function RequestCoverage({ entry, canWrite, enabled, t }: { entry: CatalogEntry; canWrite: boolean; enabled: boolean; t: Translations }) {
  const [open, setOpen] = useState(false);
  const named = coverageFor(entry, canWrite, enabled);
  if (named === null) return null;
  return (
    <div className="mt-1 space-y-1">
      <span className="block text-xs text-muted-foreground">{t.submissions.notAssessed}</span>
      <Button size="sm" variant="outline" onClick={() => setOpen(true)}>{t.submissions.requestCoverage}</Button>
      {open && <SubmissionDialog named={named} copy={t.submissions} onClose={() => setOpen(false)} />}
    </div>
  );
}

/** Report an incorrect match under a `covered` build that names a finding (#623), with the release its answer came from. */
export function ReportMatch({ entry, canWrite, enabled, release, t }: { entry: CatalogEntry; canWrite: boolean; enabled: boolean; release: string | null; t: Translations }) {
  const [open, setOpen] = useState(false);
  const correction = correctionFor(entry, canWrite, enabled, release);
  if (correction === null) return null;
  return (
    <div className="mt-1">
      <Button size="sm" variant="outline" onClick={() => setOpen(true)}>{t.submissions.reportMatch}</Button>
      {open && <SubmissionDialog {...correction} copy={t.submissions} onClose={() => setOpen(false)} />}
    </div>
  );
}
