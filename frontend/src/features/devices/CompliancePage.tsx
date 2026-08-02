import { MOCK_COMPLIANCE, complianceRate } from "@/features/devices/complianceMockData";
import { useLocale } from "@/i18n/LocaleContext";

export function CompliancePage() {
  const { t } = useLocale();

  return (
    <section className="space-y-6">
      <div>
        <p className="text-sm font-medium text-muted-foreground">{t.compliance.eyebrow}</p>
        <h1 className="text-3xl font-bold tracking-tight">{t.compliance.title}</h1>
        <p className="mt-1 text-sm text-muted-foreground">{t.compliance.description}</p>
      </div>

      <div className="rounded-lg border border-dashed bg-muted/30 p-3 text-sm text-muted-foreground">
        {t.common.previewBanner}
      </div>

      <div className="overflow-x-auto rounded-lg border bg-card">
        <table className="w-full text-sm">
          <thead className="border-b bg-muted/30 text-left text-muted-foreground">
            <tr>
              <th className="px-4 py-2 font-medium">{t.compliance.tableApplication}</th>
              <th className="px-4 py-2 font-medium">{t.compliance.tableCompliantDevices}</th>
              <th className="px-4 py-2 font-medium">{t.compliance.tableNonCompliantDevices}</th>
              <th className="px-4 py-2 font-medium">{t.compliance.tableComplianceRate}</th>
            </tr>
          </thead>
          <tbody>
            {MOCK_COMPLIANCE.length === 0 && (
              <tr>
                <td className="px-4 py-4 text-muted-foreground" colSpan={4}>
                  {t.compliance.empty}
                </td>
              </tr>
            )}
            {MOCK_COMPLIANCE.map((row) => (
              <tr key={row.id} className="border-b last:border-0">
                <td className="px-4 py-2 font-medium">{row.appName}</td>
                <td className="px-4 py-2">{row.compliantDevices}</td>
                <td className="px-4 py-2">{row.nonCompliantDevices}</td>
                <td className="px-4 py-2">{complianceRate(row)}%</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
