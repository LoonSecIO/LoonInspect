import { MOCK_APPLICATIONS } from "@/features/devices/applicationsMockData";
import { useLocale } from "@/i18n/LocaleContext";

export function ApplicationsOverviewPage() {
  const { t } = useLocale();

  function triStateLabel(value: boolean | null): string {
    if (value === null) return "—";
    return value ? t.devices.yes : t.devices.no;
  }

  return (
    <section className="space-y-6">
      <div className="rounded-lg border border-dashed bg-muted/30 p-3 text-sm text-muted-foreground">
        {t.common.previewBanner}
      </div>

      <div className="overflow-x-auto rounded-lg border bg-card">
        <table className="w-full text-sm">
          <thead className="border-b bg-muted/30 text-left text-muted-foreground">
            <tr>
              <th className="px-4 py-2 font-medium">{t.applications.tableName}</th>
              <th className="px-4 py-2 font-medium">{t.applications.tableBundleId}</th>
              <th className="px-4 py-2 font-medium">{t.applications.tableVersion}</th>
              <th className="px-4 py-2 font-medium">{t.applications.tableInstalls}</th>
              <th className="px-4 py-2 font-medium">{t.applications.tableCompliant}</th>
              <th className="px-4 py-2 font-medium">{t.applications.tablePatchAvailable}</th>
            </tr>
          </thead>
          <tbody>
            {MOCK_APPLICATIONS.length === 0 && (
              <tr>
                <td className="px-4 py-4 text-muted-foreground" colSpan={6}>
                  {t.applications.empty}
                </td>
              </tr>
            )}
            {MOCK_APPLICATIONS.map((app) => (
              <tr key={app.id} className="border-b last:border-0">
                <td className="px-4 py-2 font-medium">{app.name}</td>
                <td className="px-4 py-2">{app.bundleId}</td>
                <td className="px-4 py-2">{app.version}</td>
                <td className="px-4 py-2">{app.installCount}</td>
                <td className="px-4 py-2">{triStateLabel(app.compliant)}</td>
                <td className="px-4 py-2">{triStateLabel(app.patchAvailable)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <p className="text-sm text-muted-foreground">{t.applications.total(MOCK_APPLICATIONS.length)}</p>
    </section>
  );
}
