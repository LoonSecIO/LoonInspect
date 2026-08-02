import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { ConnectionForm } from "@/features/mdm/ConnectionForm";
import { deleteConnection, listConnections } from "@/features/mdm/api";
import type { MdmConnection } from "@/features/mdm/types";
import { useLocale } from "@/i18n/LocaleContext";

type FormMode = "closed" | "create" | number;

export function ConnectionsPage() {
  const { t } = useLocale();
  const [connections, setConnections] = useState<MdmConnection[]>([]);
  const [loading, setLoading] = useState(true);
  const [formMode, setFormMode] = useState<FormMode>("closed");
  const [pendingDeleteId, setPendingDeleteId] = useState<number | null>(null);
  const [deleting, setDeleting] = useState(false);

  async function refresh() {
    setLoading(true);
    try {
      setConnections(await listConnections());
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    refresh();
  }, []);

  async function handleDelete(id: number) {
    setDeleting(true);
    try {
      await deleteConnection(id);
      setPendingDeleteId(null);
      await refresh();
    } finally {
      setDeleting(false);
    }
  }

  const editingConnection =
    typeof formMode === "number" ? connections.find((c) => c.id === formMode) : undefined;

  return (
    <section className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm font-medium text-muted-foreground">{t.settings.eyebrow}</p>
          <h1 className="text-3xl font-bold tracking-tight">{t.settings.title}</h1>
        </div>
        {formMode === "closed" && <Button onClick={() => setFormMode("create")}>{t.settings.addConnection}</Button>}
      </div>

      {formMode !== "closed" && (
        <ConnectionForm
          connection={editingConnection}
          onSaved={() => {
            setFormMode("closed");
            refresh();
          }}
          onCancel={() => setFormMode("closed")}
        />
      )}

      <div className="overflow-x-auto rounded-lg border bg-card">
        <table className="w-full text-sm">
          <thead className="border-b bg-muted/30 text-left text-muted-foreground">
            <tr>
              <th className="px-4 py-2 font-medium">{t.settings.tableName}</th>
              <th className="px-4 py-2 font-medium">{t.settings.tableProvider}</th>
              <th className="px-4 py-2 font-medium">{t.settings.tableBaseUrl}</th>
              <th className="px-4 py-2 font-medium">{t.settings.tablePatchMgmt}</th>
              <th className="px-4 py-2 font-medium">{t.settings.tableStatus}</th>
              <th className="px-4 py-2" />
            </tr>
          </thead>
          <tbody>
            {loading && (
              <tr>
                <td className="px-4 py-4 text-muted-foreground" colSpan={6}>
                  {t.settings.loading}
                </td>
              </tr>
            )}
            {!loading && connections.length === 0 && (
              <tr>
                <td className="px-4 py-4 text-muted-foreground" colSpan={6}>
                  {t.settings.empty}
                </td>
              </tr>
            )}
            {connections.map((connection) => (
              <tr key={connection.id} className="border-b last:border-0">
                <td className="px-4 py-2">{connection.name}</td>
                <td className="px-4 py-2">{connection.provider}</td>
                <td className="px-4 py-2">{connection.baseUrl}</td>
                <td className="px-4 py-2">{connection.patchManagementProvider}</td>
                <td className="px-4 py-2">{connection.isActive ? t.settings.active : t.settings.inactive}</td>
                <td className="px-4 py-2">
                  {pendingDeleteId === connection.id ? (
                    <div className="flex items-center justify-end gap-2">
                      <span className="text-xs text-muted-foreground">{t.settings.deleteConfirm(connection.name)}</span>
                      <Button
                        variant="destructive"
                        size="sm"
                        disabled={deleting}
                        onClick={() => handleDelete(connection.id)}
                      >
                        {deleting ? t.settings.deleting : t.settings.confirm}
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        disabled={deleting}
                        onClick={() => setPendingDeleteId(null)}
                      >
                        {t.settings.cancel}
                      </Button>
                    </div>
                  ) : (
                    <div className="flex justify-end gap-2">
                      <Button variant="outline" size="sm" onClick={() => setFormMode(connection.id)}>
                        {t.settings.edit}
                      </Button>
                      <Button variant="destructive" size="sm" onClick={() => setPendingDeleteId(connection.id)}>
                        {t.settings.delete}
                      </Button>
                    </div>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
