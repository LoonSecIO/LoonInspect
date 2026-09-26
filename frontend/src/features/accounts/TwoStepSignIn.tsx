import { useEffect, useState, type FormEvent } from "react";
import { Check, Copy } from "lucide-react";
import { QRCodeSVG } from "qrcode.react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { getMfaStatus } from "@/features/accounts/api";
import { CLOSED, confirmCode, renewCodes, startSetUp, type Move, type Panel } from "@/features/accounts/twoStep";
import type { MfaStatus } from "@/features/accounts/types";
import type { Translations } from "@/i18n/en";
import { useLocale, type Locale } from "@/i18n/LocaleContext";

/** What the status read answered. A read that failed is unknown, never "off" (#150). */
export type StatusRead = { state: "loading" } | { state: "failed" } | { state: "ready"; status: MfaStatus };
type Handlers = Record<"setUp" | "renew" | "cancel" | "copyCodes" | "saved", () => void> & {
  code: (value: string) => void;
  confirm: (event: FormEvent) => void;
};

interface ViewProps {
  read: StatusRead;
  panel: Panel;
  copy: Translations["myAccount"]["twoStep"];
  locale: Locale;
  busy?: boolean;
  code?: string;
  copied?: "idle" | "copied" | "refused";
  on?: Partial<Handlers>;
}

/** The section for one status and one panel step; stateless, so the node test lane renders it. */
export function TwoStepSignInView({ read, panel, copy, locale, busy = false, code = "", copied = "idle", on = {} }: ViewProps) {
  const status = read.state === "ready" ? read.status : null;
  const failure = panel.step !== "codes" ? panel.error : copied === "refused" ? copy.copyRefused : null;
  const since = status?.confirmedAt ? new Date(status.confirmedAt).toLocaleDateString(locale, { dateStyle: "medium" }) : "—";

  return (
    <div className="max-w-md space-y-4 rounded-lg border bg-card p-4">
      <h2 className="text-lg font-semibold">{copy.title}</h2>
      {read.state === "loading" && <p className="text-sm text-muted-foreground">{copy.loading}</p>}
      {read.state === "failed" && <p className="text-sm text-destructive">{copy.unreadable}</p>}
      {status?.enrolled && (
        <p className="text-sm"><span className="font-medium">{copy.onSince(since)}</span> {copy.codesLeft(status.recoveryCodesRemaining)}</p>
      )}
      {status?.enrolled && panel.step === "closed" && <Button variant="outline" onClick={on.renew}>{copy.renew}</Button>}
      {status && !status.enrolled && panel.step === "closed" && (
        <>
          <p className="text-sm text-muted-foreground">{status.pending ? copy.pending : copy.off}</p>
          <Button onClick={on.setUp} disabled={busy}>{busy ? copy.starting : copy.setUp}</Button>
        </>
      )}

      {panel.step === "scan" && (
        <form onSubmit={on.confirm} className="space-y-3">
          <p className="text-sm">{copy.scan}</p>
          {/* Black on white with the standard four-module margin, so it scans in dark mode too. */}
          <QRCodeSVG value={panel.enrolment.otpauthUrl} size={192} marginSize={4} title={copy.qrTitle} />
          <p className="text-sm text-muted-foreground">{copy.manual}</p>
          <code className="block select-all break-all rounded-md border bg-background px-3 py-2 font-mono text-sm">{panel.enrolment.secret}</code>
          <label htmlFor="mfaCode" className="block text-sm font-medium">{copy.codeLabel}</label>
          <Input id="mfaCode" required inputMode="numeric" autoComplete="one-time-code" minLength={6} maxLength={32}
            value={code} onChange={(event) => on.code?.(event.target.value)} />
          <div className="flex gap-2">
            <Button type="submit" disabled={busy}>{busy ? copy.confirming : copy.confirm}</Button>
            <Button variant="ghost" onClick={on.cancel} disabled={busy}>{copy.cancel}</Button>
          </div>
        </form>
      )}

      {panel.step === "renew" && (
        <form onSubmit={on.confirm} className="space-y-3">
          <label htmlFor="renewCode" className="block text-sm font-medium">{copy.renewLabel}</label>
          <Input id="renewCode" required inputMode="numeric" autoComplete="one-time-code" minLength={6} maxLength={32}
            value={code} onChange={(event) => on.code?.(event.target.value)} />
          <div className="flex gap-2">
            <Button type="submit" disabled={busy}>{busy ? copy.confirming : copy.renewSubmit}</Button>
            <Button variant="ghost" onClick={on.cancel} disabled={busy}>{copy.cancel}</Button>
          </div>
        </form>
      )}

      {panel.step === "codes" && (
        <div className="space-y-3 rounded-lg border border-primary/40 bg-primary/5 p-4">
          <p className="text-sm font-medium">{copy.codesTitle}</p>
          <p className="text-sm text-muted-foreground">{copy.codesOnce}</p>
          <pre className="select-all rounded-md border bg-background px-3 py-2 font-mono text-sm">{panel.codes.join("\n")}</pre>
          <div className="flex gap-2">
            <Button variant="outline" size="sm" onClick={on.copyCodes}>
              {copied === "copied" ? <Check className="mr-2 h-4 w-4" /> : <Copy className="mr-2 h-4 w-4" />}
              {copied === "copied" ? copy.copied : copy.copy}
            </Button>
            <Button size="sm" onClick={on.saved}>{copy.saved}</Button>
          </div>
        </div>
      )}

      {failure && <p role="alert" className="text-sm text-destructive">{failure}</p>}
    </div>
  );
}

/** My Account › Two-step sign-in (#653): the status, and set-up inline on the page. */
export function TwoStepSignIn() {
  const { t, locale } = useLocale();
  const copy = t.myAccount.twoStep;
  const [reads, setReads] = useState(0);
  const [read, setRead] = useState<StatusRead>({ state: "loading" });
  const [panel, setPanel] = useState<Panel>(CLOSED);
  const [busy, setBusy] = useState(false);
  const [code, setCode] = useState("");
  const [copied, setCopied] = useState<ViewProps["copied"]>("idle");

  // A re-read turns the status back to asking in the render that asked for it, never from
  // the effect; the guard compares the effect's whole dependency array (CONTRIBUTING, #479).
  const [asked, setAsked] = useState(reads);
  if (asked !== reads) {
    setAsked(reads);
    setRead({ state: "loading" });
  }

  useEffect(() => {
    let live = true;
    getMfaStatus()
      .then((status) => live && setRead({ state: "ready", status }))
      .catch(() => live && setRead({ state: "failed" }));
    return () => {
      live = false;
    };
  }, [reads]);

  function apply(move: Move) {
    setPanel(move.panel);
    setCode("");
    setCopied("idle");
    setBusy(false);
    if (move.refresh) setReads((count) => count + 1);
  }

  function run(next: Promise<Move>) {
    setBusy(true);
    void next.then(apply);
  }

  const on: Handlers = {
    setUp: () => run(startSetUp(copy.failed)),
    renew: () => apply({ panel: { step: "renew", error: null }, refresh: false }),
    code: setCode,
    confirm: (event) => {
      event.preventDefault();
      if (panel.step === "scan") run(confirmCode(panel.enrolment, code, copy.failed));
      if (panel.step === "renew") run(renewCodes(code, copy.failed));
    },
    // Cancelling leaves an unconfirmed set-up on the server; the re-read says so.
    cancel: () => apply({ panel: CLOSED, refresh: true }),
    // `navigator.clipboard` is absent from a page served over plain HTTP anywhere but localhost.
    copyCodes: () => {
      if (panel.step !== "codes") return;
      const codes = panel.codes.join("\n");
      Promise.resolve()
        .then(() => navigator.clipboard.writeText(codes))
        .then(() => setCopied("copied"), () => setCopied("refused"));
    },
    // The codes go with the panel: shown once.
    saved: () => setPanel(CLOSED)
  };

  return <TwoStepSignInView {...{ read, panel, copy, locale, busy, code, copied, on }} />;
}
