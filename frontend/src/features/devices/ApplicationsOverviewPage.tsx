import { useEffect, useState } from "react";
import { ChevronDown, ChevronRight } from "lucide-react";
import { Input } from "@/components/ui/input";
import { listApplications, type Application } from "@/features/devices/applicationsApi";
import { useLocale } from "@/i18n/LocaleContext";

export function ApplicationsOverviewPage() {
  const { t } = useLocale();

  const [applications, setApplications] = useState<Application[]>([]);
  const [total, setTotal] = useState(0);
  const [search, setSearch] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  useEffect(() => {
    let cancelled = false;
    setLoading(true);

    // Debounced so typing in the filter doesn't fire a query per keystroke.
    const handle = setTimeout(() => {
      listApplications({ search: search || undefined, limit: 200 })
        .then((response) => {
          if (cancelled) return;
          setApplications(response.items);
          setTotal(response.total);
          setError(null);
        })
        .catch(() => {
          if (!cancelled) setError(t.applications.errorLoading);
        })
        .finally(() => {
          if (!cancelled) setLoading(false);
        });
    }, 250);

    return () => {
      cancelled = true;
      clearTimeout(handle);
    };
  }, [search, t]);

  function toggle(appHash: string) {
    setExpanded((current) => {
      const next = new Set(current);
      if (next.has(appHash)) next.delete(appHash);
      else next.add(appHash);
      return next;
    });
  }

  function triStateLabel(value: boolean | null): string {
    if (value === null) return "—";
    return value ? t.devices.yes : t.devices.no;
  }

  return (
    <section className="space-y-4">
      <Input
        placeholder={t.applications.searchPlaceholder}
        value={search}
        onChange={(event) => setSearch(event.target.value)}
        className="max-w-sm"
      />

      {error && <p className="text-sm text-destructive">{error}</p>}

      <div className="overflow-x-auto rounded-lg border bg-card">
        <table className="w-full text-sm">
          <thead className="border-b bg-muted/30 text-left text-muted-foreground">
            <tr>
              <th className="px-4 py-2 font-medium">{t.applications.tableName}</th>
              <th className="px-4 py-2 font-medium">{t.applications.tableBundleId}</th>
              <th className="px-4 py-2 font-medium">{t.applications.tableVersions}</th>
              <th className="px-4 py-2 text-right font-medium">{t.applications.tableDevices}</th>
            </tr>
          </thead>
          <tbody>
            {loading && (
              <tr>
                <td className="px-4 py-4 text-muted-foreground" colSpan={4}>
                  {t.applications.loading}
                </td>
              </tr>
            )}
            {!loading && applications.length === 0 && (
              <tr>
                <td className="px-4 py-4 text-muted-foreground" colSpan={4}>
                  {t.applications.empty}
                </td>
              </tr>
            )}
            {applications.map((app) => {
              const isOpen = expanded.has(app.appHash);
              return [
                <tr
                  key={app.appHash}
                  className="cursor-pointer border-b last:border-0 hover:bg-accent/40"
                  onClick={() => toggle(app.appHash)}
                >
                  <td className="px-4 py-2 font-medium">
                    <span className="inline-flex items-center gap-1">
                      {isOpen ? (
                        <ChevronDown className="h-4 w-4 text-muted-foreground" />
                      ) : (
                        <ChevronRight className="h-4 w-4 text-muted-foreground" />
                      )}
                      {app.name}
                    </span>
                  </td>
                  <td className="px-4 py-2 font-mono text-xs text-muted-foreground">
                    {app.bundleId}
                  </td>
                  <td className="px-4 py-2">{app.versionCount}</td>
                  <td className="px-4 py-2 text-right font-medium tabular-nums">
                    {app.deviceCount}
                  </td>
                </tr>,

                isOpen && (
                  <tr key={`${app.appHash}-versions`} className="border-b last:border-0 bg-muted/20">
                    <td colSpan={4} className="px-4 py-3">
                      <table className="w-full text-xs">
                        <thead className="text-left text-muted-foreground">
                          <tr>
                            <th className="py-1 font-medium">{t.applications.tableVersion}</th>
                            <th className="py-1 font-medium">{t.applications.tableShortVersion}</th>
                            <th className="py-1 font-medium">{t.applications.tableCompliant}</th>
                            <th className="py-1 font-medium">{t.applications.tablePatchAvailable}</th>
                            <th className="py-1 font-medium">{t.applications.tableVersionHash}</th>
                            <th className="py-1 text-right font-medium">
                              {t.applications.tableDevices}
                            </th>
                          </tr>
                        </thead>
                        <tbody>
                          {app.versions.map((version) => (
                            <tr key={version.versionHash}>
                              <td className="py-1">{version.version || "—"}</td>
                              <td className="py-1">{version.shortVersion ?? "—"}</td>
                              <td className="py-1">{triStateLabel(version.isCompliant)}</td>
                              <td className="py-1">{triStateLabel(version.patchAvailable)}</td>
                              <td
                                className="py-1 font-mono text-muted-foreground"
                                title={version.versionHash}
                              >
                                {version.versionHash.slice(0, 12)}…
                              </td>
                              <td className="py-1 text-right tabular-nums">
                                {version.deviceCount}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </td>
                  </tr>
                )
              ];
            })}
          </tbody>
        </table>
      </div>

      <p className="text-sm text-muted-foreground">{t.applications.total(total)}</p>
    </section>
  );
}
