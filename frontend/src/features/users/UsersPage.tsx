import { MOCK_USERS } from "@/features/users/usersMockData";
import { useLocale } from "@/i18n/LocaleContext";

const sourceLabels: Record<string, string> = {
  jamf: "Jamf",
  simplemdm: "SimpleMDM"
};

export function UsersPage() {
  const { t } = useLocale();

  return (
    <section className="space-y-6">
      <div>
        <p className="text-sm font-medium text-muted-foreground">{t.users.eyebrow}</p>
        <h1 className="text-3xl font-bold tracking-tight">{t.users.title}</h1>
        <p className="mt-1 text-sm text-muted-foreground">{t.users.description}</p>
      </div>

      <div className="rounded-lg border border-dashed bg-muted/30 p-3 text-sm text-muted-foreground">
        {t.common.previewBanner}
      </div>

      <div className="overflow-x-auto rounded-lg border bg-card">
        <table className="w-full text-sm">
          <thead className="border-b bg-muted/30 text-left text-muted-foreground">
            <tr>
              <th className="px-4 py-2 font-medium">{t.users.tableName}</th>
              <th className="px-4 py-2 font-medium">{t.users.tableUsername}</th>
              <th className="px-4 py-2 font-medium">{t.users.tableEmail}</th>
              <th className="px-4 py-2 font-medium">{t.users.tableDepartment}</th>
              <th className="px-4 py-2 font-medium">{t.users.tableSource}</th>
              <th className="px-4 py-2 font-medium">{t.users.tableAssignedDevices}</th>
              <th className="px-4 py-2 font-medium">{t.users.tableLoggedInDevices}</th>
              <th className="px-4 py-2 font-medium">{t.users.tableLastSeen}</th>
            </tr>
          </thead>
          <tbody>
            {MOCK_USERS.length === 0 && (
              <tr>
                <td className="px-4 py-4 text-muted-foreground" colSpan={8}>
                  {t.users.empty}
                </td>
              </tr>
            )}
            {MOCK_USERS.map((user) => (
              <tr key={user.id} className="border-b last:border-0">
                <td className="px-4 py-2 font-medium">{user.displayName}</td>
                <td className="px-4 py-2">{user.username}</td>
                <td className="px-4 py-2">{user.email ?? "—"}</td>
                <td className="px-4 py-2">{user.department ?? "—"}</td>
                <td className="px-4 py-2">{sourceLabels[user.source] ?? user.source}</td>
                <td className="px-4 py-2">
                  {user.assignedDevices.length > 0 ? user.assignedDevices.join(", ") : "—"}
                </td>
                <td className="px-4 py-2">
                  {user.loggedInDevices.length > 0 ? user.loggedInDevices.join(", ") : "—"}
                </td>
                <td className="px-4 py-2">
                  {user.lastSeenAt ? new Date(user.lastSeenAt).toLocaleString() : "—"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <p className="text-sm text-muted-foreground">{t.users.total(MOCK_USERS.length)}</p>
    </section>
  );
}
