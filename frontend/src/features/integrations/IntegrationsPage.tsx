import { INTEGRATION_GROUPS } from "@/features/integrations/data";
import { IntegrationCard } from "@/features/integrations/IntegrationCard";
import { useLocale } from "@/i18n/LocaleContext";

export function IntegrationsPage() {
  const { t } = useLocale();

  return (
    <section className="space-y-8">
      <div>
        <p className="text-sm font-medium text-muted-foreground">{t.integrations.eyebrow}</p>
        <h1 className="text-3xl font-bold tracking-tight">{t.integrations.title}</h1>
        <p className="mt-1 text-sm text-muted-foreground">{t.integrations.description}</p>
      </div>

      {INTEGRATION_GROUPS.map((group) => (
        <div key={group.id} className="space-y-3">
          <h2 className="text-lg font-semibold tracking-tight">{t.integrations.groups[group.id]}</h2>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
            {group.vendors.map((vendor) => (
              <IntegrationCard key={vendor.id} vendor={vendor} />
            ))}
          </div>
        </div>
      ))}
    </section>
  );
}
