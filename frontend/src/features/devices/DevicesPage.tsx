import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router";
import { FilterBar } from "@/features/devices/FilterBar";
import { listDevices } from "@/features/devices/api";
import type { Device, DeviceFilters, VersionOperator } from "@/features/devices/types";

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
  const [searchParams, setSearchParams] = useSearchParams();
  const filters = useMemo(() => filtersFromSearchParams(searchParams), [searchParams]);

  const [devices, setDevices] = useState<Device[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);

    listDevices(filters)
      .then((response) => {
        if (cancelled) return;
        setDevices(response.items);
        setTotal(response.total);
      })
      .catch(() => {
        if (!cancelled) setError("Failed to load devices.");
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [filters]);

  return (
    <section className="space-y-6">
      <div>
        <p className="text-sm font-medium text-muted-foreground">Inventory</p>
        <h1 className="text-3xl font-bold tracking-tight">Devices</h1>
      </div>

      <FilterBar filters={filters} onChange={(next) => setSearchParams(searchParamsFromFilters(next))} />

      <div className="overflow-x-auto rounded-lg border bg-card">
        <table className="w-full text-sm">
          <thead className="border-b bg-muted/30 text-left text-muted-foreground">
            <tr>
              <th className="px-4 py-2 font-medium">Hostname</th>
              <th className="px-4 py-2 font-medium">Serial</th>
              <th className="px-4 py-2 font-medium">OS Version</th>
              <th className="px-4 py-2 font-medium">Site</th>
              <th className="px-4 py-2 font-medium">Department</th>
              <th className="px-4 py-2 font-medium">Managed</th>
              <th className="px-4 py-2 font-medium">Supervised</th>
              <th className="px-4 py-2 font-medium">Last check-in</th>
            </tr>
          </thead>
          <tbody>
            {loading && (
              <tr>
                <td className="px-4 py-4 text-muted-foreground" colSpan={8}>
                  Loading...
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
                  No devices match these filters.
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
                <td className="px-4 py-2">{device.managed === null ? "—" : device.managed ? "Yes" : "No"}</td>
                <td className="px-4 py-2">
                  {device.supervised === null ? "—" : device.supervised ? "Yes" : "No"}
                </td>
                <td className="px-4 py-2">
                  {device.lastCheckIn ? new Date(device.lastCheckIn).toLocaleString() : "—"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <p className="text-sm text-muted-foreground">
        {total} device{total === 1 ? "" : "s"} total
      </p>
    </section>
  );
}
