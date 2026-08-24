import { MOCK_GROUPS } from "@/features/devices/groupsMockData";
import { useLocale } from "@/i18n/LocaleContext";

const sourceLabels: Record<string, string> = {
  jamf: "Jamf",
  loonsecio: "LoonSecIO"
};

export function GroupsPage() {
  const { t } = useLocale();

  const typeLabels: Record<string, string> = {
    smart: t.groups.typeSmart,
    static: t.groups.typeStatic
  };

  return (
    <section className="space-y-6">
      <div>
        <p className="text-sm font-medium text-muted-foreground">{t.groups.eyebrow}</p>
        <h1 className="text-3xl font-bold tracking-tight">{t.groups.title}</h1>
        <p className="mt-1 text-sm text-muted-foreground">{t.groups.description}</p>
      </div>

      <div className="rounded-lg border border-dashed bg-muted/30 p-3 text-sm text-muted-foreground">
        {t.common.previewBanner}
      </div>

      <div className="overflow-x-auto rounded-lg border bg-card">
        <table className="w-full text-sm">
          <thead className="border-b bg-muted/30 text-left text-muted-foreground">
            <tr>
              <th className="px-4 py-2 font-medium">{t.groups.tableName}</th>
              <th className="px-4 py-2 font-medium">{t.groups.tableType}</th>
              <th className="px-4 py-2 font-medium">{t.groups.tableDescription}</th>
              <th className="px-4 py-2 font-medium">{t.groups.tableDevices}</th>
              <th className="px-4 py-2 font-medium">{t.groups.tableSource}</th>
            </tr>
          </thead>
          <tbody>
            {MOCK_GROUPS.length === 0 && (
              <tr>
                <td className="px-4 py-4 text-muted-foreground" colSpan={5}>
                  {t.groups.empty}
                </td>
              </tr>
            )}
            {MOCK_GROUPS.map((group) => (
              <tr key={group.id} className="border-b last:border-0">
                <td className="px-4 py-2 font-medium">{group.name}</td>
                <td className="px-4 py-2">{typeLabels[group.type]}</td>
                <td className="px-4 py-2">{group.description}</td>
                <td className="px-4 py-2">{group.deviceCount}</td>
                <td className="px-4 py-2">{sourceLabels[group.source] ?? group.source}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <p className="text-sm text-muted-foreground">{t.groups.total(MOCK_GROUPS.length)}</p>
    </section>
  );
}
