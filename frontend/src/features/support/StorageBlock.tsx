import { useEffect, useState } from "react";
import { formatBytes } from "@/features/support/formatBytes";
import { getStorage, type StorageResponse, type StorageTable } from "@/features/system/api";
import { useLocale } from "@/i18n/LocaleContext";

type Loaded = { state: "ready"; storage: StorageResponse } | { state: "failed" } | null;

/**
 * Settings › Support › **Storage** (#786): what the database holds, table by table, how much
 * each takes, and the clock each one is on — the answer that otherwise needs `psql` as the
 * superuser and the arithmetic in KNOWN_ISSUES §1–§3. Sizes and row estimates are Postgres's
 * own for this database, every tenant in it; the clocks are the settings in force right now.
 *
 * Rendered only for readers who hold SYSTEM_READ, like the Updates block above it: how big an
 * instance is, is the operator's question. Nothing here runs a purge or a VACUUM.
 */
export function StorageBlock() {
  const { t, locale } = useLocale();
  const ts = t.support.storage;
  const [loaded, setLoaded] = useState<Loaded>(null);

  useEffect(() => {
    let cancelled = false;
    getStorage()
      .then((storage) => {
        if (!cancelled) setLoaded({ state: "ready", storage });
      })
      .catch(() => {
        if (!cancelled) setLoaded({ state: "failed" });
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const rows = (n: number) => new Intl.NumberFormat(locale).format(n);
  const kept = (table: StorageTable): string => {
    if (!table.present) return ts.absent;
    if (table.retentionDays === null) {
      return table.setting ? `${ts.forever} · ${ts.boundBy(table.setting)}` : ts.forever;
    }
    return table.setting ? `${ts.days(table.retentionDays)} · ${ts.bySetting(table.setting)}` : ts.days(table.retentionDays);
  };

  const group = (area: StorageTable["area"], heading: string, help: string, tables: StorageTable[]) => (
    <>
      <tr className="bg-muted/40">
        <th scope="colgroup" colSpan={4} className="px-3 py-2 text-left font-medium">
          {heading}
          <span className="ml-2 font-normal text-muted-foreground">{help}</span>
        </th>
      </tr>
      {tables
        .filter((table) => table.area === area)
        .map((table) => (
          <tr key={table.table} className="border-b last:border-b-0">
            <td className="px-3 py-2 font-mono text-xs">{table.table}</td>
            <td className="px-3 py-2 text-right tabular-nums">{table.present ? rows(table.rowsEstimate) : "—"}</td>
            <td className="px-3 py-2 text-right tabular-nums">{table.present ? formatBytes(table.bytes, locale) : "—"}</td>
            <td className="px-3 py-2">
              {kept(table)}
              {ts.qualifiers[table.table] && (
                <span className="block text-xs text-muted-foreground">{ts.qualifiers[table.table]}</span>
              )}
            </td>
          </tr>
        ))}
    </>
  );

  return (
    <div className="space-y-3 rounded-lg border bg-card p-4">
      <h2 className="text-lg font-semibold">{ts.heading}</h2>
      <p className="max-w-3xl text-sm text-muted-foreground">{ts.help}</p>
      {loaded === null && <p className="text-sm text-muted-foreground">{ts.loading}</p>}
      {loaded?.state === "failed" && <p className="text-sm text-muted-foreground">{ts.errorLoading}</p>}
      {loaded?.state === "ready" && (
        <>
          <p className="text-sm">
            {ts.database(formatBytes(loaded.storage.databaseBytes, locale), new Date(loaded.storage.measuredAt).toLocaleString(locale))}
          </p>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="border-b text-left text-muted-foreground">
                <tr>
                  <th className="px-3 py-2 font-medium">{ts.colTable}</th>
                  <th className="px-3 py-2 text-right font-medium">{ts.colRows}</th>
                  <th className="px-3 py-2 text-right font-medium">{ts.colSize}</th>
                  <th className="px-3 py-2 font-medium">{ts.colKept}</th>
                </tr>
              </thead>
              <tbody>
                {group("record", ts.recordHeading, ts.recordHelp, loaded.storage.tables)}
                {group("machinery", ts.machineryHeading, ts.machineryHelp, loaded.storage.tables)}
              </tbody>
            </table>
          </div>
          <p className="max-w-3xl text-xs text-muted-foreground">{ts.note}</p>
        </>
      )}
    </div>
  );
}
