import type { DeviceFilters, VersionOperator } from "@/features/devices/types";

interface FilterBarProps {
  filters: DeviceFilters;
  onChange: (filters: DeviceFilters) => void;
}

const inputClasses =
  "rounded-md border border-input bg-background px-3 py-2 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring";

const versionOperatorLabels: Record<VersionOperator, string> = {
  eq: "is",
  lt: "older than",
  lte: "at or older than",
  gt: "newer than",
  gte: "at or newer than",
  regex: "matches regex"
};

function triState(value: boolean | undefined): string {
  if (value === undefined) return "any";
  return value ? "true" : "false";
}

function fromTriState(value: string): boolean | undefined {
  if (value === "any") return undefined;
  return value === "true";
}

export function FilterBar({ filters, onChange }: FilterBarProps) {
  function update(patch: Partial<DeviceFilters>) {
    onChange({ ...filters, ...patch, page: 1 });
  }

  return (
    <div className="space-y-3 rounded-lg border bg-card p-4">
      <div className="flex flex-wrap gap-3">
        <input
          className={`${inputClasses} min-w-[200px] flex-1`}
          placeholder="Search hostname or serial number..."
          value={filters.q ?? ""}
          onChange={(e) => update({ q: e.target.value || undefined })}
        />
        <div className="min-w-[200px] flex-1 space-y-1">
          <input
            className={`${inputClasses} w-full`}
            placeholder="Ask AI to filter devices..."
            value={filters.ai ?? ""}
            onChange={(e) => update({ ai: e.target.value || undefined })}
          />
          <p className="text-xs text-muted-foreground">
            Natural-language filtering is coming soon — this doesn't affect results yet.
          </p>
        </div>
      </div>

      <div className="flex flex-wrap gap-3">
        <div className="flex items-center gap-2">
          <select
            className={inputClasses}
            value={filters.osVersionOperator ?? "eq"}
            onChange={(e) => update({ osVersionOperator: e.target.value as VersionOperator })}
          >
            {(Object.keys(versionOperatorLabels) as VersionOperator[]).map((operator) => (
              <option key={operator} value={operator}>
                OS version {versionOperatorLabels[operator]}
              </option>
            ))}
          </select>
          <input
            className={inputClasses}
            placeholder={filters.osVersionOperator === "regex" ? "Regex, e.g. ^14\\." : "e.g. 14.5"}
            value={filters.osVersion ?? ""}
            onChange={(e) => update({ osVersion: e.target.value || undefined })}
          />
        </div>
        <input
          className={inputClasses}
          placeholder="Site"
          value={filters.site ?? ""}
          onChange={(e) => update({ site: e.target.value || undefined })}
        />
        <input
          className={inputClasses}
          placeholder="Building"
          value={filters.building ?? ""}
          onChange={(e) => update({ building: e.target.value || undefined })}
        />
        <input
          className={inputClasses}
          placeholder="Department"
          value={filters.department ?? ""}
          onChange={(e) => update({ department: e.target.value || undefined })}
        />

        <label className="flex items-center gap-2 text-sm text-muted-foreground">
          Managed
          <select
            className={inputClasses}
            value={triState(filters.managed)}
            onChange={(e) => update({ managed: fromTriState(e.target.value) })}
          >
            <option value="any">Any</option>
            <option value="true">Yes</option>
            <option value="false">No</option>
          </select>
        </label>

        <label className="flex items-center gap-2 text-sm text-muted-foreground">
          Supervised
          <select
            className={inputClasses}
            value={triState(filters.supervised)}
            onChange={(e) => update({ supervised: fromTriState(e.target.value) })}
          >
            <option value="any">Any</option>
            <option value="true">Yes</option>
            <option value="false">No</option>
          </select>
        </label>
      </div>
    </div>
  );
}
