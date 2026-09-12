import { useEffect, useState } from "react";
import { Download, RefreshCw, Send } from "lucide-react";
import { Button } from "@/components/ui/button";
import { PERMISSIONS } from "@/features/auth/types";
import { useHasPermission } from "@/features/auth/store";
import {
  getDataSharing,
  previewExchange,
  resetSubmissionUuid,
  sendExchangeNow,
  updateDataSharing,
  type DataSharingSettings,
  type ShareLogEntry,
  type SharingTier
} from "@/features/system/api";
import { endpointHost, sendNowAvailability } from "@/features/system/sendNow";
import { ApiError } from "@/config/api";
import { env } from "@/config/env";
import { useLocale } from "@/i18n/LocaleContext";

const TIERS: SharingTier[] = ["reveal", "keys", "off"];

export function DataSharingPage() {
  const { t } = useLocale();
  const canWrite = useHasPermission(PERMISSIONS.SYSTEM_WRITE);

  const [settings, setSettings] = useState<DataSharingSettings | null>(null);
  const [globsDraft, setGlobsDraft] = useState("");
  const [preview, setPreview] = useState<string | null>(null);
  const [previewLoading, setPreviewLoading] = useState(false);
  // Send now (#408): the row the last send wrote, which replaces the preview in the box,
  // and the server's refusal when a click meets one the page could not foresee.
  const [sent, setSent] = useState<ShareLogEntry | null>(null);
  const [sending, setSending] = useState(false);
  const [sendRefusal, setSendRefusal] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    getDataSharing()
      .then((loaded) => {
        setSettings(loaded);
        setGlobsDraft(loaded.excludeGlobs.join("\n"));
      })
      .catch(() => setError(t.system.sharing.loadFailed));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function apply(update: { tier?: SharingTier; excludeGlobs?: string[] }) {
    try {
      setError(null);
      setSettings(await updateDataSharing(update));
    } catch {
      setError(t.system.sharing.saveFailed);
    }
  }

  async function handleResetUuid() {
    try {
      setError(null);
      setSettings(await resetSubmissionUuid());
    } catch {
      setError(t.system.sharing.saveFailed);
    }
  }

  async function handleDownloadLog() {
    try {
      setError(null);
      // Raw fetch rather than apiRequest: the endpoint streams NDJSON, not JSON.
      const response = await fetch(`${env.apiBaseUrl}/system/share-log`, { credentials: "include" });
      if (!response.ok) throw new Error(String(response.status));
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = "share-log.ndjson";
      anchor.click();
      URL.revokeObjectURL(url);
    } catch {
      setError(t.system.sharing.loadFailed);
    }
  }

  async function handlePreview() {
    setPreviewLoading(true);
    try {
      setError(null);
      setPreview(JSON.stringify(await previewExchange(), null, 2));
      setSent(null);
    } catch {
      setError(t.system.sharing.loadFailed);
    } finally {
      setPreviewLoading(false);
    }
  }

  async function handleSend() {
    setSending(true);
    setSendRefusal(null);
    try {
      setError(null);
      const result = await sendExchangeNow();
      setSent(result.exchange);
      setPreview(null);
      setSettings(result.settings);
    } catch (caught) {
      // A 409 is a refusal before anything was attempted, and its detail is the
      // sentence; anything else never reached the exchange at all.
      setSendRefusal(
        caught instanceof ApiError && caught.status === 409 && caught.detail
          ? caught.detail
          : t.system.sharing.sendRequestFailed
      );
    } finally {
      setSending(false);
    }
  }

  if (!settings) {
    return <p className="text-sm text-muted-foreground">{error ?? t.auth.loading}</p>;
  }

  // One reason locks these controls, and it is the permission: changing what this
  // instance shares is a consent decision reserved to administrators
  // (`permissions.py`, SYSTEM_WRITE). The environment override used to lock them too,
  // which contradicted the backend, whose PUT is written to persist a choice made
  // while overridden so it survives the override being lifted (#302). Now the
  // override is explained above and the choice is recorded beneath it.
  const locked = !canWrite;
  const sendAvailability = sendNowAvailability(settings, canWrite);

  function outcomeLabel(outcome: string | null): string {
    switch (outcome) {
      case "sent":
        return t.system.sharing.outcomeSent;
      case "failed":
        return t.system.sharing.outcomeFailed;
      default:
        return outcome ?? "?";
    }
  }
  const tierLabels: Record<SharingTier, { label: string; description: string }> = {
    reveal: { label: t.system.sharing.tierReveal, description: t.system.sharing.tierRevealHelp },
    keys: { label: t.system.sharing.tierKeys, description: t.system.sharing.tierKeysHelp },
    off: { label: t.system.sharing.tierOff, description: t.system.sharing.tierOffHelp }
  };

  return (
    <div className="max-w-3xl space-y-8">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">{t.nav.dataSharing}</h1>
        <p className="mt-1 text-sm text-muted-foreground">{t.system.sharing.pageDescription}</p>
      </div>

      {settings.envDisabled && (
        <p className="rounded-md border border-amber-500/40 bg-amber-500/10 px-4 py-3 text-sm">
          {t.system.sharing.envLocked}
        </p>
      )}

      {!canWrite && (
        <p className="rounded-md border bg-muted/40 px-4 py-3 text-sm text-muted-foreground">
          {t.system.sharing.readOnlyRole}
        </p>
      )}

      {error && (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      )}

      <section className="space-y-3 rounded-lg border bg-card p-6">
        <h2 className="font-semibold">{t.system.sharing.tierHeading}</h2>
        {settings.envDisabled && (
          <p className="text-xs text-muted-foreground">{t.system.sharing.tierRecordedWhileOverridden}</p>
        )}
        {TIERS.map((tier) => (
          <label
            key={tier}
            className={`flex cursor-pointer items-start gap-3 rounded-md border p-3 ${
              settings.tier === tier ? "border-primary bg-primary/5" : "border-input"
            } ${locked ? "cursor-not-allowed opacity-60" : ""}`}
          >
            <input
              type="radio"
              name="sharing-tier"
              className="mt-1"
              checked={settings.tier === tier}
              disabled={locked}
              onChange={() => void apply({ tier })}
            />
            <span>
              <span className="block text-sm font-medium">{tierLabels[tier].label}</span>
              <span className="block text-xs text-muted-foreground">
                {tierLabels[tier].description}
              </span>
            </span>
          </label>
        ))}
      </section>

      <section className="space-y-3 rounded-lg border bg-card p-6">
        <h2 className="font-semibold">{t.system.sharing.disclosureHeading}</h2>
        <p className="text-sm text-muted-foreground">{t.system.sharing.disclosureShared}</p>
        <p className="text-sm text-muted-foreground">{t.system.sharing.disclosureNever}</p>
        <p className="text-sm text-muted-foreground">{t.system.sharing.disclosureReveals}</p>
        <p className="text-sm text-muted-foreground">{t.system.sharing.disclosurePseudonym}</p>
      </section>

      <section className="space-y-3 rounded-lg border bg-card p-6">
        <h2 className="font-semibold">{t.system.sharing.previewHeading}</h2>
        <p className="text-sm text-muted-foreground">{t.system.sharing.previewHelp}</p>
        {sendAvailability !== "hidden" && (
          <p className="text-sm text-muted-foreground">{t.system.sharing.sendHelp}</p>
        )}
        <div className="flex flex-wrap gap-2">
          <Button type="button" variant="outline" onClick={handlePreview} disabled={previewLoading || sending}>
            {previewLoading ? t.auth.loading : t.system.sharing.previewButton}
          </Button>
          {sendAvailability !== "hidden" && (
            <Button
              type="button"
              variant="outline"
              onClick={handleSend}
              disabled={sendAvailability !== "ready" || sending}
            >
              <Send aria-hidden="true" className="mr-1.5 h-4 w-4" />
              {sending ? t.system.sharing.sending : t.system.sharing.sendButton}
            </Button>
          )}
        </div>
        {sendAvailability === "blockedEnv" && (
          <p className="text-xs text-muted-foreground">{t.system.sharing.sendBlockedEnv}</p>
        )}
        {sendAvailability === "blockedOff" && (
          <p className="text-xs text-muted-foreground">{t.system.sharing.sendBlockedOff}</p>
        )}
        {sending && <p className="text-xs text-muted-foreground">{t.system.sharing.sendingHelp}</p>}
        {sendRefusal && (
          <p role="alert" className="text-sm text-destructive">
            {sendRefusal}
          </p>
        )}
        {sent !== null ? (
          // The past, where the future was: the row the send wrote, never the corpus link
          // the answer may have carried — that is a capability and is never shown.
          <div className="space-y-2">
            <p className="text-sm">
              {sent.outcome === "sent"
                ? t.system.sharing.resultSent(new Date(sent.occurredAt).toLocaleString(), endpointHost(sent.endpoint))
                : t.system.sharing.resultFailed(new Date(sent.occurredAt).toLocaleString(), endpointHost(sent.endpoint))}
            </p>
            {sent.error && <p className="text-sm text-destructive">{sent.error}</p>}
            {sent.revealsShed && <p className="text-xs text-muted-foreground">{t.system.sharing.revealsShed}</p>}
            <pre className="max-h-96 overflow-auto rounded-md border bg-muted/40 p-3 text-xs">
              {JSON.stringify(sent.payload, null, 2)}
            </pre>
          </div>
        ) : (
          preview !== null && (
            <pre className="max-h-96 overflow-auto rounded-md border bg-muted/40 p-3 text-xs">
              {preview}
            </pre>
          )
        )}
      </section>

      <section className="space-y-3 rounded-lg border bg-card p-6">
        <h2 className="font-semibold">{t.system.sharing.identityHeading}</h2>
        <p className="text-sm text-muted-foreground">{t.system.sharing.identityHelp}</p>
        <p className="flex items-center gap-3 text-sm">
          <code className="rounded bg-muted px-2 py-1 font-mono text-xs">
            {settings.submissionUuid}
          </code>
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={handleResetUuid}
            disabled={locked}
          >
            <RefreshCw aria-hidden="true" className="mr-1.5 h-3.5 w-3.5" />
            {t.system.sharing.resetUuid}
          </Button>
        </p>
      </section>

      <section className="space-y-3 rounded-lg border bg-card p-6">
        <h2 className="font-semibold">{t.system.sharing.excludeHeading}</h2>
        <p className="text-sm text-muted-foreground">{t.system.sharing.excludeHelp}</p>
        <textarea
          className="min-h-24 w-full rounded-md border border-input bg-background px-3 py-2 font-mono text-xs"
          value={globsDraft}
          disabled={locked}
          onChange={(event) => setGlobsDraft(event.target.value)}
          onBlur={() =>
            void apply({ excludeGlobs: globsDraft.split("\n").map((g) => g.trim()).filter(Boolean) })
          }
          placeholder="com.acme.*"
        />
      </section>

      <section className="space-y-3 rounded-lg border bg-card p-6">
        <h2 className="font-semibold">{t.system.sharing.logHeading}</h2>
        <p className="text-sm text-muted-foreground">
          {t.system.sharing.lastExchange}:{" "}
          {settings.lastExchangeAt === null
            ? // "never" keeps meaning "no exchange has been recorded" — an off-tier instance
              // logs nothing, and that is a different fact from a skipped one.
              t.system.sharing.neverExchanged
            : settings.lastExchangeOutcome === "skipped_env"
              ? // The daily proof the override is biting gets its own sentence, not a code
                // in parentheses.
                t.system.sharing.skippedEnv(new Date(settings.lastExchangeAt).toLocaleString())
              : `${new Date(settings.lastExchangeAt).toLocaleString()} (${outcomeLabel(settings.lastExchangeOutcome)}${
                  settings.lastExchangeRevealsShed ? `, ${t.system.sharing.revealsShed}` : ""
                })`}
        </p>
        {settings.lastExchangeOutcome === "failed" && settings.lastExchangeError && (
          // The row's own sentence (#408): before, "(failed)" was all the page said, and
          // the reason lived only in the download below.
          <p className="text-sm text-destructive">{settings.lastExchangeError}</p>
        )}
        <p className="text-sm text-muted-foreground">{t.system.sharing.logHelp}</p>
        <Button type="button" variant="outline" onClick={handleDownloadLog}>
          <Download aria-hidden="true" className="mr-1.5 h-4 w-4" />
          {t.system.sharing.downloadLog}
        </Button>
      </section>
    </div>
  );
}
