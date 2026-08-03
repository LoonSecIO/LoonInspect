import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { listFeatureFlags, updateFeatureFlag } from "@/features/settings/api";
import type { FeatureFlag } from "@/features/settings/types";
import { useLocale } from "@/i18n/LocaleContext";

export function FeatureFlagsPage() {
  const { t } = useLocale();
  const [flags, setFlags] = useState<FeatureFlag[]>([]);
  const [loading, setLoading] = useState(true);
  const [pendingKey, setPendingKey] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    listFeatureFlags()
      .then((response) => {
        if (!cancelled) setFlags(response);
      })
      .catch(() => {
        if (!cancelled) setError(t.featureFlags.errorLoading);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [t]);

  function handleToggle(flag: FeatureFlag) {
    setPendingKey(flag.key);
    setError(null);

    updateFeatureFlag(flag.key, !flag.enabled)
      .then((updated) => {
        setFlags((current) => current.map((f) => (f.key === updated.key ? updated : f)));
      })
      .catch(() => setError(t.featureFlags.errorUpdating))
      .finally(() => setPendingKey(null));
  }

  return (
    <section className="space-y-6">
      <div>
        <p className="text-sm font-medium text-muted-foreground">{t.settings.eyebrow}</p>
        <h1 className="text-3xl font-bold tracking-tight">{t.featureFlags.title}</h1>
        <p className="mt-1 text-sm text-muted-foreground">{t.featureFlags.description}</p>
      </div>

      {error && <p className="text-sm text-destructive">{error}</p>}

      <div className="divide-y rounded-lg border bg-card">
        {loading && <p className="p-4 text-sm text-muted-foreground">{t.featureFlags.loading}</p>}
        {!loading && flags.length === 0 && (
          <p className="p-4 text-sm text-muted-foreground">{t.featureFlags.empty}</p>
        )}
        {flags.map((flag) => (
          <div key={flag.key} className="flex items-center justify-between gap-4 p-4">
            <div>
              <p className="text-sm font-medium">{flag.label}</p>
              <p className="text-sm text-muted-foreground">{flag.description}</p>
            </div>
            <Button
              variant={flag.enabled ? "default" : "outline"}
              size="sm"
              disabled={pendingKey === flag.key}
              onClick={() => handleToggle(flag)}
            >
              {flag.enabled ? t.featureFlags.on : t.featureFlags.off}
            </Button>
          </div>
        ))}
      </div>
    </section>
  );
}
