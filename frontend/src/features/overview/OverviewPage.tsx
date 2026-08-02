import { Button } from "@/components/ui/button";
import { useLocale } from "@/i18n/LocaleContext";

export function OverviewPage() {
  const { t } = useLocale();

  return (
    <section className="space-y-6">
      <div>
        <p className="text-sm font-medium text-muted-foreground">{t.overview.eyebrow}</p>
        <h1 className="text-3xl font-bold tracking-tight">{t.overview.title}</h1>
        <p className="mt-2 max-w-2xl text-muted-foreground">{t.overview.description}</p>
      </div>

      <div className="rounded-lg border bg-card p-6 text-card-foreground shadow-sm">
        <h2 className="text-xl font-semibold">{t.overview.apiConnectionTitle}</h2>
        <p className="mt-2 text-sm text-muted-foreground">
          {t.overview.apiConnectionPrefix} <code className="rounded bg-muted px-1 py-0.5">/api</code>{" "}
          {t.overview.apiConnectionSuffix}
        </p>

        <div className="mt-4">
          <Button>{t.overview.checkApiStatus}</Button>
        </div>
      </div>
    </section>
  );
}
