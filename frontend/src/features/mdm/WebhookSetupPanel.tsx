import { useCallback, useEffect, useState, type FormEvent } from "react";
import { AlertTriangle, Check, Copy, KeyRound, RotateCw } from "lucide-react";
import { Button } from "@/components/ui/button";
import { ApiError } from "@/config/api";
import { env } from "@/config/env";
import { listRuns, updateConnection } from "@/features/mdm/api";
import type { MdmConnection, MdmConnectionInput, Run } from "@/features/mdm/types";
import {
  JAMF_WEBHOOKS_GUIDE,
  generateSecret,
  headerObject,
  originWarning,
  receivePatch,
  webhookOrigin,
  webhookStatus,
  webhookUrl
} from "@/features/mdm/webhookSetup";
import { useLocale } from "@/i18n/LocaleContext";

interface WebhookSetupPanelProps {
  connection: MdmConnection;
  canWrite: boolean;
  onConnectionChanged: (connection: MdmConnection) => void;
}

const inputClasses =
  "w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring";

const COPIED_VISIBLE_MS = 2000;

type LastRun = { state: "loading" } | { state: "none" } | { state: "error" } | { state: "found"; run: Run };

/** Webhook setup for one Jamf Pro connection (#406): everything Jamf Pro's webhook form
 *  asks for, on the row an operator looks for it on.
 *
 *  The secret is generated here, in the browser, and shown once as the header object
 *  Jamf Pro takes. It lives in this component's state and nowhere else — not storage,
 *  not a URL — and the server never sends it back (docs/auth-design.md §4.7). Lose it
 *  and Rotate makes a new one; that is the whole recovery story, ruled by Kyle on #406. */
export function WebhookSetupPanel({ connection, canWrite, onConnectionChanged }: WebhookSetupPanelProps) {
  const { t } = useLocale();
  const tw = t.collections.webhookSetup;

  const [revealed, setRevealed] = useState<string | null>(null);
  const [copied, setCopied] = useState<"url" | "header" | null>(null);
  const [confirmRotate, setConfirmRotate] = useState(false);
  const [ownOpen, setOwnOpen] = useState(false);
  const [own, setOwn] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastRun, setLastRun] = useState<LastRun>({ state: "loading" });

  const origin = webhookOrigin(env.apiBaseUrl, window.location.origin);
  const url = webhookUrl(origin, connection.id);
  const warning = originWarning(origin);
  const status = webhookStatus(connection);

  // The proof it works, on the page where it is set up. Read once when the panel opens;
  // a refused webhook leaves no run, so an empty answer points at the container log.
  useEffect(() => {
    let cancelled = false;
    listRuns(connection.id, 1, "webhook")
      .then((rows) => {
        if (!cancelled) setLastRun(rows[0] ? { state: "found", run: rows[0] } : { state: "none" });
      })
      .catch(() => {
        if (!cancelled) setLastRun({ state: "error" });
      });
    return () => {
      cancelled = true;
    };
  }, [connection.id]);

  useEffect(() => {
    if (!copied) return;
    const handle = window.setTimeout(() => setCopied(null), COPIED_VISIBLE_MS);
    return () => window.clearTimeout(handle);
  }, [copied]);

  const copy = useCallback((what: "url" | "header", text: string) => {
    // Best-effort, like the Overview strip: a browser that refuses clipboard access
    // leaves the text on screen to select by hand.
    void navigator.clipboard?.writeText(text).then(
      () => setCopied(what),
      () => undefined
    );
  }, []);

  async function save(patch: Pick<MdmConnectionInput, "capabilityWebhooks" | "webhookSecret">) {
    setBusy(true);
    setError(null);
    try {
      const updated = await updateConnection(connection.id, patch);
      onConnectionChanged(updated);
      // Only after the save lands: a header shown for a secret the server refused would
      // be pasted into Jamf Pro and fail there instead.
      if (patch.webhookSecret !== undefined) setRevealed(headerObject(patch.webhookSecret));
      setConfirmRotate(false);
      setOwnOpen(false);
      setOwn("");
    } catch (caught) {
      setError(caught instanceof ApiError && caught.detail ? caught.detail : tw.error);
    } finally {
      setBusy(false);
    }
  }

  function handleOwn(event: FormEvent) {
    event.preventDefault();
    if (own) void save({ webhookSecret: own });
  }

  function lastRunLine(): string {
    switch (lastRun.state) {
      case "loading":
        return "";
      case "none":
        return tw.noRun;
      case "error":
        return tw.lastRunUnreadable;
      case "found":
        return tw.lastRun(
          new Date(lastRun.run.startedAt).toLocaleString(),
          tw.runOutcomes[lastRun.run.status] ?? lastRun.run.status
        );
    }
  }

  const statusClass = status === "receiving" ? "text-green-600" : "text-destructive";

  return (
    <div className="space-y-4 rounded-lg border bg-muted/20 p-4 text-sm">
      <div>
        <p className="font-medium">{tw.title}</p>
        <p className="text-muted-foreground">{tw.intro}</p>
      </div>

      <div className="space-y-1">
        <div className="flex flex-wrap items-center gap-3">
          <span className={`font-medium ${statusClass}`}>{tw.status[status]}</span>
          {canWrite && status !== "inactive" && (
            <Button
              size="sm"
              variant={connection.capabilityWebhooks ? "outline" : "default"}
              disabled={busy}
              onClick={() => void save(receivePatch(!connection.capabilityWebhooks, connection.hasWebhookSecret))}
            >
              {connection.capabilityWebhooks ? tw.turnOff : tw.turnOn}
            </Button>
          )}
        </div>
        {canWrite && !connection.capabilityWebhooks && !connection.hasWebhookSecret && status !== "inactive" && (
          <p className="text-xs text-muted-foreground">{tw.turnOnMakesSecret}</p>
        )}
        {lastRunLine() && <p className="text-xs text-muted-foreground">{lastRunLine()}</p>}
      </div>

      <div className="space-y-1">
        <p className="font-medium">{tw.addressLabel}</p>
        <div className="flex items-center gap-2">
          <code className="flex-1 overflow-x-auto rounded-md border bg-background px-3 py-2 font-mono text-xs">{url}</code>
          <Button variant="outline" size="sm" onClick={() => copy("url", url)}>
            {copied === "url" ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
            <span className="ml-2">{copied === "url" ? tw.copied : tw.copy}</span>
          </Button>
        </div>
        <p className="text-xs text-muted-foreground">{tw.addressHint}</p>
        {warning && (
          <p className="flex items-start gap-1 text-xs text-amber-600 dark:text-amber-400">
            <AlertTriangle aria-hidden="true" className="mt-0.5 h-3 w-3 shrink-0" />
            {tw.originWarning[warning]}
          </p>
        )}
      </div>

      <div className="space-y-2">
        <div>
          <p className="font-medium">{tw.headerLabel}</p>
          <p className="text-xs text-muted-foreground">{tw.headerHint}</p>
        </div>

        {revealed ? (
          <div className="space-y-2 rounded-md border border-primary/40 bg-primary/5 p-3">
            <div className="flex items-center gap-2">
              <code className="flex-1 overflow-x-auto rounded-md border bg-background px-3 py-2 font-mono text-xs">
                {revealed}
              </code>
              <Button variant="outline" size="sm" onClick={() => copy("header", revealed)}>
                {copied === "header" ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
                <span className="ml-2">{copied === "header" ? tw.copied : tw.copy}</span>
              </Button>
            </div>
            <p className="flex items-center gap-2 text-xs font-medium">
              <KeyRound aria-hidden="true" className="h-3 w-3 text-primary" />
              {tw.headerOnce}
            </p>
            <Button variant="ghost" size="sm" onClick={() => setRevealed(null)}>
              {tw.headerDone}
            </Button>
          </div>
        ) : (
          <p className="text-muted-foreground">{connection.hasWebhookSecret ? tw.secretSet : tw.noSecret}</p>
        )}

        {canWrite && !revealed && confirmRotate && (
          <div className="space-y-2 rounded-md border border-destructive/40 bg-destructive/5 p-3">
            <p className="font-medium">{tw.rotateConfirmTitle}</p>
            <p>{tw.rotateConfirm}</p>
            <div className="flex gap-2">
              <Button
                size="sm"
                variant="destructive"
                disabled={busy}
                onClick={() => void save({ webhookSecret: generateSecret() })}
              >
                {tw.rotateNow}
              </Button>
              <Button size="sm" variant="outline" disabled={busy} onClick={() => setConfirmRotate(false)}>
                {t.settings.cancel}
              </Button>
            </div>
          </div>
        )}

        {canWrite && !revealed && !confirmRotate && (
          <div className="flex flex-wrap items-center gap-3">
            {connection.hasWebhookSecret ? (
              <Button size="sm" variant="outline" disabled={busy} onClick={() => setConfirmRotate(true)}>
                <RotateCw className="mr-1 h-3 w-3" />
                {tw.rotate}
              </Button>
            ) : (
              <Button size="sm" disabled={busy} onClick={() => void save({ webhookSecret: generateSecret() })}>
                <KeyRound className="mr-1 h-3 w-3" />
                {tw.generate}
              </Button>
            )}
            <button
              type="button"
              className="text-xs font-medium text-primary underline-offset-2 hover:underline"
              onClick={() => setOwnOpen((current) => !current)}
            >
              {ownOpen ? tw.ownSecretHide : tw.ownSecret}
            </button>
          </div>
        )}

        {canWrite && !revealed && !confirmRotate && ownOpen && (
          <form onSubmit={handleOwn} className="space-y-2">
            <label className="block space-y-1">
              <span className="font-medium">{tw.ownSecretLabel}</span>
              <input
                type="password"
                autoComplete="off"
                className={inputClasses}
                value={own}
                onChange={(e) => setOwn(e.target.value)}
              />
            </label>
            <p className="text-xs text-muted-foreground">{tw.ownSecretHint}</p>
            {connection.hasWebhookSecret && <p className="text-xs text-destructive">{tw.rotateConfirm}</p>}
            <Button type="submit" size="sm" disabled={busy || !own}>
              {tw.ownSecretSave}
            </Button>
          </form>
        )}
      </div>

      <div className="space-y-1">
        <p className="font-medium">{tw.jamfTitle}</p>
        <ol className="list-decimal space-y-0.5 pl-5">
          {tw.jamfSteps.map((step) => (
            <li key={step}>{step}</li>
          ))}
        </ol>
        <a
          href={JAMF_WEBHOOKS_GUIDE}
          target="_blank"
          rel="noreferrer"
          className="text-xs font-medium text-primary underline-offset-2 hover:underline"
        >
          {tw.guide}
        </a>
      </div>

      {!canWrite && <p className="text-xs text-muted-foreground">{tw.readOnly}</p>}
      {error && (
        <p role="alert" className="rounded-md border border-destructive/40 bg-destructive/5 px-3 py-2 text-destructive">
          {error}
        </p>
      )}
    </div>
  );
}
