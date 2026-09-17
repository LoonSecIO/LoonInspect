import type { DeviceFilters, VersionOperator } from "@/features/devices/types";
import { useLocale } from "@/i18n/LocaleContext";

interface FilterBarProps {
  filters: DeviceFilters;
  /** The corpus answering for this organization, or null (#535). The chips are offered only
   *  where there is something to select: under `off` the filter is refused, and a control
   *  that can only produce a refusal is worse than no control. */
  corpusAsOf: string | null;
  onChange: (filters: DeviceFilters) => void;
}

/** The two chips, and the one URL key they share. Mutually exclusive by construction: KEV
 *  narrows *with findings* rather than being a second axis, so they are one value and not
 *  two booleans that could ask for something the endpoint does not mean. */
const VULN_CHIPS = ["findings", "kev"] as const;

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

export function FilterBar({ filters, corpusAsOf, onChange }: FilterBarProps) {
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
      </div>

      <div className="flex flex-wrap gap-3">
        {/* The operator and its value stay a pair, but the pair wraps too: on a phone
            the two together are wider than the screen, and an unwrappable row is the
            one thing left that can push the page past the viewport (#349). */}
        <div className="flex flex-wrap items-center gap-2">
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

        {/* The one control over `?includeDeparted=true` (#475): off by default, and visible. */}
        <label className="flex items-center gap-2 text-sm text-muted-foreground">
          <input
            type="checkbox"
            checked={filters.includeDeparted ?? false}
            onChange={(e) => update({ includeDeparted: e.target.checked || undefined })}
          />
          {t.devices.showDeparted}
        </label>
      </div>

      {/* URL-carried like every control above, so a shared link asks the same question and
          page 2 of it is still that question. Clicking the chip that is on clears it. */}
      {corpusAsOf !== null && (
        <div className="flex flex-wrap gap-2">
          {VULN_CHIPS.map((value) => (
            <button
              key={value}
              type="button"
              aria-pressed={filters.vuln === value}
              className={`rounded-full border px-3 py-1 text-xs ${
                filters.vuln === value ? "bg-primary text-primary-foreground" : "bg-muted text-muted-foreground"
              }`}
              onClick={() => update({ vuln: filters.vuln === value ? undefined : value })}
            >
              {value === "kev" ? t.devices.onKevChip : t.devices.withFindingsChip}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
