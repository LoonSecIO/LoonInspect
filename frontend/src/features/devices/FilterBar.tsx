import type { DeviceFilters, VersionOperator } from "@/features/devices/types";
import { useLocale } from "@/i18n/LocaleContext";

interface FilterBarProps {
  filters: DeviceFilters;
  onChange: (filters: DeviceFilters) => void;
}

const inputClasses =
  "rounded-md border border-input bg-background px-3 py-2 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring";

function triState(value: boolean | undefined): string {
  if (value === undefined) return "any";
  return value ? "true" : "false";
}

function fromTriState(value: string): boolean | undefined {
  if (value === "any") return undefined;
  return value === "true";
}

export function FilterBar({ filters, onChange }: FilterBarProps) {
  const { t } = useLocale();

  function update(patch: Partial<DeviceFilters>) {
    onChange({ ...filters, ...patch, page: 1 });
  }

  return (
    <div className="space-y-3 rounded-lg border bg-card p-4">
      <div className="flex flex-wrap gap-3">
        <input
          className={`${inputClasses} min-w-[200px] flex-1`}
          placeholder={t.devices.searchPlaceholder}
          value={filters.q ?? ""}
          onChange={(e) => update({ q: e.target.value || undefined })}
        />
        <div className="min-w-[200px] flex-1 space-y-1">
          <input
            className={`${inputClasses} w-full`}
            placeholder={t.devices.aiPlaceholder}
            value={filters.ai ?? ""}
            onChange={(e) => update({ ai: e.target.value || undefined })}
          />
          <p className="text-xs text-muted-foreground">{t.devices.aiHint}</p>
        </div>
      </div>

      <div className="flex flex-wrap gap-3">
        <div className="flex items-center gap-2">
          <select
            className={inputClasses}
            value={filters.osVersionOperator ?? "eq"}
            onChange={(e) => update({ osVersionOperator: e.target.value as VersionOperator })}
          >
            {(Object.keys(t.devices.osVersionOperators) as VersionOperator[]).map((operator) => (
              <option key={operator} value={operator}>
                {t.devices.osVersionPrefix} {t.devices.osVersionOperators[operator]}
              </option>
            ))}
          </select>
          <input
            className={inputClasses}
            placeholder={filters.osVersionOperator === "regex" ? t.devices.osVersionRegexPlaceholder : t.devices.osVersionPlaceholder}
            value={filters.osVersion ?? ""}
            onChange={(e) => update({ osVersion: e.target.value || undefined })}
          />
        </div>
        <input
          className={inputClasses}
          placeholder={t.devices.sitePlaceholder}
          value={filters.site ?? ""}
          onChange={(e) => update({ site: e.target.value || undefined })}
        />
        <input
          className={inputClasses}
          placeholder={t.devices.buildingPlaceholder}
          value={filters.building ?? ""}
          onChange={(e) => update({ building: e.target.value || undefined })}
        />
        <input
          className={inputClasses}
          placeholder={t.devices.departmentPlaceholder}
          value={filters.department ?? ""}
          onChange={(e) => update({ department: e.target.value || undefined })}
        />

        <label className="flex items-center gap-2 text-sm text-muted-foreground">
          {t.devices.managed}
          <select
            className={inputClasses}
            value={triState(filters.managed)}
            onChange={(e) => update({ managed: fromTriState(e.target.value) })}
          >
            <option value="any">{t.devices.any}</option>
            <option value="true">{t.devices.yes}</option>
            <option value="false">{t.devices.no}</option>
          </select>
        </label>

        <label className="flex items-center gap-2 text-sm text-muted-foreground">
          {t.devices.supervised}
          <select
            className={inputClasses}
            value={triState(filters.supervised)}
            onChange={(e) => update({ supervised: fromTriState(e.target.value) })}
          >
            <option value="any">{t.devices.any}</option>
            <option value="true">{t.devices.yes}</option>
            <option value="false">{t.devices.no}</option>
          </select>
        </label>
      </div>
    </div>
  );
}
