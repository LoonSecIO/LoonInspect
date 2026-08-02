import { useLocale } from "@/i18n/LocaleContext";

export function VulnerabilitiesPage() {
  const { t } = useLocale();

  return (
    <section className="space-y-2">
      <p className="text-sm font-medium text-muted-foreground">{t.vulnerabilities.eyebrow}</p>
      <h1 className="text-3xl font-bold tracking-tight">{t.vulnerabilities.title}</h1>
      <p className="max-w-2xl text-muted-foreground">{t.vulnerabilities.description}</p>
    </section>
  );
}
