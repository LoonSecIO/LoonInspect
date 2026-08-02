import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { ConnectionForm } from "@/features/mdm/ConnectionForm";
import { deleteConnection, listConnections } from "@/features/mdm/api";
import type { MdmConnection } from "@/features/mdm/types";

type FormMode = "closed" | "create" | number;

export function ConnectionsPage() {
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
          <p className="text-sm font-medium text-muted-foreground">Settings</p>
          <h1 className="text-3xl font-bold tracking-tight">MDM Connections</h1>
        </div>
        {formMode === "closed" && <Button onClick={() => setFormMode("create")}>Add connection</Button>}
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
              <th className="px-4 py-2 font-medium">Name</th>
              <th className="px-4 py-2 font-medium">Provider</th>
              <th className="px-4 py-2 font-medium">Base URL</th>
              <th className="px-4 py-2 font-medium">Patch mgmt</th>
              <th className="px-4 py-2 font-medium">Status</th>
              <th className="px-4 py-2" />
            </tr>
          </thead>
          <tbody>
            {loading && (
              <tr>
                <td className="px-4 py-4 text-muted-foreground" colSpan={6}>
                  Loading...
                </td>
              </tr>
            )}
            {!loading && connections.length === 0 && (
              <tr>
                <td className="px-4 py-4 text-muted-foreground" colSpan={6}>
                  No connections yet.
                </td>
              </tr>
            )}
            {connections.map((connection) => (
              <tr key={connection.id} className="border-b last:border-0">
                <td className="px-4 py-2">{connection.name}</td>
                <td className="px-4 py-2">{connection.provider}</td>
                <td className="px-4 py-2">{connection.baseUrl}</td>
                <td className="px-4 py-2">{connection.patchManagementProvider}</td>
                <td className="px-4 py-2">{connection.isActive ? "Active" : "Inactive"}</td>
                <td className="px-4 py-2">
                  {pendingDeleteId === connection.id ? (
                    <div className="flex items-center justify-end gap-2">
                      <span className="text-xs text-muted-foreground">Delete "{connection.name}"?</span>
                      <Button
                        variant="destructive"
                        size="sm"
                        disabled={deleting}
                        onClick={() => handleDelete(connection.id)}
                      >
                        {deleting ? "Deleting..." : "Confirm"}
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        disabled={deleting}
                        onClick={() => setPendingDeleteId(null)}
                      >
                        Cancel
                      </Button>
                    </div>
                  ) : (
                    <div className="flex justify-end gap-2">
                      <Button variant="outline" size="sm" onClick={() => setFormMode(connection.id)}>
                        Edit
                      </Button>
                      <Button variant="destructive" size="sm" onClick={() => setPendingDeleteId(connection.id)}>
                        Delete
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
