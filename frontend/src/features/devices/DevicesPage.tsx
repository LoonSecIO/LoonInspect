import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router";
import { Button } from "@/components/ui/button";
import { FilterBar } from "@/features/devices/FilterBar";
import { listDevices } from "@/features/devices/api";
import type { Device, DeviceFilters, VersionOperator } from "@/features/devices/types";
import { useLocale } from "@/i18n/LocaleContext";

function filtersFromSearchParams(params: URLSearchParams): DeviceFilters {
  const managed = params.get("managed");
  const supervised = params.get("supervised");

  return {
    q: params.get("q") ?? undefined,
    ai: params.get("ai") ?? undefined,
    osVersion: params.get("osVersion") ?? undefined,
    osVersionOperator: (params.get("osVersionOperator") as VersionOperator | null) ?? undefined,
    site: params.get("site") ?? undefined,
    building: params.get("building") ?? undefined,
    department: params.get("department") ?? undefined,
    managed: managed === null ? undefined : managed === "true",
    supervised: supervised === null ? undefined : supervised === "true",
    page: params.get("page") ? Number(params.get("page")) : 1
  };
}

function searchParamsFromFilters(filters: DeviceFilters): URLSearchParams {
  const params = new URLSearchParams();
  if (filters.q) params.set("q", filters.q);
  if (filters.ai) params.set("ai", filters.ai);
  if (filters.osVersion) {
    params.set("osVersion", filters.osVersion);
    params.set("osVersionOperator", filters.osVersionOperator ?? "eq");
  }
  if (filters.site) params.set("site", filters.site);
  if (filters.building) params.set("building", filters.building);
  if (filters.department) params.set("department", filters.department);
  if (filters.managed !== undefined) params.set("managed", String(filters.managed));
  if (filters.supervised !== undefined) params.set("supervised", String(filters.supervised));
  if (filters.page && filters.page !== 1) params.set("page", String(filters.page));
  return params;
}

export function DevicesPage() {
  const { t } = useLocale();
  const [searchParams, setSearchParams] = useSearchParams();
  const filters = useMemo(() => filtersFromSearchParams(searchParams), [searchParams]);

  const [devices, setDevices] = useState<Device[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const pageSize = 50;

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);

    // Debounced so typing in the filter doesn't fire a query per keystroke.
    const handle = setTimeout(() => {
      listDevices({ ...filters, pageSize })
        .then((response) => {
          if (cancelled) return;
          setDevices(response.items);
          setTotal(response.total);
        })
        .catch(() => {
          if (!cancelled) setError(t.devices.errorLoading);
        })
        .finally(() => {
          if (!cancelled) setLoading(false);
        });
    }, 250);

    return () => {
      cancelled = true;
      clearTimeout(handle);
    };
  }, [filters, t]);

  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  const page = filters.page ?? 1;

  function goToPage(next: number) {
    setSearchParams(searchParamsFromFilters({ ...filters, page: next }));
  }

  return (
    <section className="space-y-6">
      <div>
        <p className="text-sm font-medium text-muted-foreground">{t.devices.eyebrow}</p>
        <h1 className="text-3xl font-bold tracking-tight">{t.devices.title}</h1>
      </div>

      <FilterBar
        filters={filters}
        onChange={(next) => setSearchParams(searchParamsFromFilters(next), { replace: true })}
      />

      <div className="overflow-x-auto rounded-lg border bg-card">
        <table className="w-full text-sm">
          <thead className="border-b bg-muted/30 text-left text-muted-foreground">
            <tr>
              <th className="px-4 py-2 font-medium">{t.devices.tableHostname}</th>
              <th className="px-4 py-2 font-medium">{t.devices.tableSerial}</th>
              <th className="px-4 py-2 font-medium">{t.devices.tableOsVersion}</th>
              <th className="px-4 py-2 font-medium">{t.devices.tableSite}</th>
              <th className="px-4 py-2 font-medium">{t.devices.tableDepartment}</th>
              <th className="px-4 py-2 font-medium">{t.devices.tableManaged}</th>
              <th className="px-4 py-2 font-medium">{t.devices.tableSupervised}</th>
              <th className="px-4 py-2 font-medium">{t.devices.tableLastCheckIn}</th>
            </tr>
          </thead>
          <tbody>
            {loading && (
              <tr>
                <td className="px-4 py-4 text-muted-foreground" colSpan={8}>
                  {t.devices.loading}
                </td>
              </tr>
            )}
            {!loading && error && (
              <tr>
                <td className="px-4 py-4 text-destructive" colSpan={8}>
                  {error}
                </td>
              </tr>
            )}
            {!loading && !error && devices.length === 0 && (
              <tr>
                <td className="px-4 py-4 text-muted-foreground" colSpan={8}>
                  {t.devices.empty}
                </td>
              </tr>
            )}
            {devices.map((device) => (
              <tr key={device.id} className="border-b last:border-0">
                <td className="px-4 py-2">{device.hostname}</td>
                <td className="px-4 py-2">{device.serialNumber}</td>
                <td className="px-4 py-2">{device.osVersion ?? "—"}</td>
                <td className="px-4 py-2">{device.site ?? "—"}</td>
                <td className="px-4 py-2">{device.department ?? "—"}</td>
                <td className="px-4 py-2">
                  {device.managed === null ? "—" : device.managed ? t.devices.yes : t.devices.no}
                </td>
                <td className="px-4 py-2">
                  {device.supervised === null ? "—" : device.supervised ? t.devices.yes : t.devices.no}
                </td>
                <td className="px-4 py-2">
                  {device.lastCheckIn ? new Date(device.lastCheckIn).toLocaleString() : "—"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="flex items-center justify-between text-sm text-muted-foreground">
        <span>{t.devices.total(total)}</span>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" disabled={page <= 1} onClick={() => goToPage(page - 1)}>
            {t.devices.previous}
          </Button>
          <span className="self-center">{t.devices.pageOf(page, totalPages)}</span>
          <Button variant="outline" size="sm" disabled={page >= totalPages} onClick={() => goToPage(page + 1)}>
            {t.devices.next}
          </Button>
        </div>
      </div>
    </section>
  );
}
