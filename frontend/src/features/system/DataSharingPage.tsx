import { useEffect, useState } from "react";
import { RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";
import { PERMISSIONS } from "@/features/auth/types";
import { useHasPermission } from "@/features/auth/store";
import {
  getDataSharing,
  previewExchange,
  resetSubmissionUuid,
  updateDataSharing,
  type DataSharingSettings,
  type SharingTier
} from "@/features/system/api";
import { useLocale } from "@/i18n/LocaleContext";

const TIERS: SharingTier[] = ["reveal", "keys", "off"];

export function DataSharingPage() {
  const { t } = useLocale();
  const canWrite = useHasPermission(PERMISSIONS.SYSTEM_WRITE);

  const [settings, setSettings] = useState<DataSharingSettings | null>(null);
  const [globsDraft, setGlobsDraft] = useState("");
  const [preview, setPreview] = useState<string | null>(null);
  const [previewLoading, setPreviewLoading] = useState(false);
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

  async function handlePreview() {
    setPreviewLoading(true);
    try {
      setError(null);
      setPreview(JSON.stringify(await previewExchange(), null, 2));
    } catch {
      setError(t.system.sharing.loadFailed);
    } finally {
      setPreviewLoading(false);
    }
  }

  if (!settings) {
    return <p className="text-sm text-muted-foreground">{error ?? t.auth.loading}</p>;
  }

  const locked = settings.envDisabled || !canWrite;
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

      {error && (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      )}

      <section className="space-y-3 rounded-lg border bg-card p-6">
        <h2 className="font-semibold">{t.system.sharing.tierHeading}</h2>
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
        <Button type="button" variant="outline" onClick={handlePreview} disabled={previewLoading}>
          {previewLoading ? t.auth.loading : t.system.sharing.previewButton}
        </Button>
        {preview !== null && (
          <pre className="max-h-96 overflow-auto rounded-md border bg-muted/40 p-3 text-xs">
            {preview}
          </pre>
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

      <p className="text-xs text-muted-foreground">
        {t.system.sharing.lastExchange}:{" "}
        {settings.lastExchangeAt ?? t.system.sharing.neverExchanged}
      </p>
    </div>
  );
}
