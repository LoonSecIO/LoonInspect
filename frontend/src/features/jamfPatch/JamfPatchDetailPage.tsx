import { useEffect, useState } from "react";
import { Link, useParams } from "react-router";
import { ChevronDown, ChevronRight, Info } from "lucide-react";
import { getJamfPatchTitle } from "@/features/jamfPatch/api";
import type { JamfPatchTitleDetail } from "@/features/jamfPatch/types";
import { ReleaseCalendar } from "@/features/jamfPatch/ReleaseCalendar";
import { RequirementsSection } from "@/features/jamfPatch/RequirementsSection";
import { RequirementsTestPanel } from "@/features/jamfPatch/RequirementsTestPanel";
import { useLocale } from "@/i18n/LocaleContext";
import type { Translations } from "@/i18n/en";

// Status colors are fixed (never themed) per the dataviz palette: critical/serious/warning/good.
const SEVERITY_COLORS = {
  critical: "#d03b3b",
  high: "#ec835a",
  medium: "#fab219",
  low: "#0ca30c"
} as const;

function VulnerabilityHeader({ t }: { t: Translations }) {
  return (
    <span className="group relative inline-flex items-center gap-1">
      {t.jamfPatch.detail.tableVulnerabilities}
      <Info tabIndex={0} className="h-3.5 w-3.5 cursor-help outline-none" />
      <span className="pointer-events-none absolute left-1/2 top-full z-10 mt-1 hidden w-max max-w-[240px] -translate-x-1/2 whitespace-normal rounded-md border bg-popover px-2 py-1 text-xs font-normal normal-case text-popover-foreground shadow-md group-hover:block group-focus-within:block">
        {t.jamfPatch.detail.vulnerabilitiesTooltip}
      </span>
    </span>
  );
}

function VulnerabilityStubCell({ t }: { t: Translations }) {
  return (
    <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-xs">
      <span className="inline-flex items-center gap-1" title={t.jamfPatch.detail.vulnCritical}>
        <span className="h-2 w-2 shrink-0 rounded-full" style={{ backgroundColor: SEVERITY_COLORS.critical }} />
        <span className="text-muted-foreground">C —</span>
      </span>
      <span className="inline-flex items-center gap-1" title={t.jamfPatch.detail.vulnHigh}>
        <span className="h-2 w-2 shrink-0 rounded-full" style={{ backgroundColor: SEVERITY_COLORS.high }} />
        <span className="text-muted-foreground">H —</span>
      </span>
      <span className="inline-flex items-center gap-1" title={t.jamfPatch.detail.vulnMedium}>
        <span className="h-2 w-2 shrink-0 rounded-full" style={{ backgroundColor: SEVERITY_COLORS.medium }} />
        <span className="text-muted-foreground">M —</span>
      </span>
      <span className="inline-flex items-center gap-1" title={t.jamfPatch.detail.vulnLow}>
        <span className="h-2 w-2 shrink-0 rounded-full" style={{ backgroundColor: SEVERITY_COLORS.low }} />
        <span className="text-muted-foreground">L —</span>
      </span>
      <span className="font-medium text-muted-foreground" title={t.jamfPatch.detail.vulnTotal}>
        Σ —
      </span>
    </div>
  );
}

/** Devices matched to the title whose installed version Jamf has not listed — ahead of the
 *  catalog (a beta) or a build Jamf never recorded. */
function unlistedDevices(title: JamfPatchTitleDetail): number {
  const listed = new Set(title.patches.map((patch) => patch.version));
  return Object.entries(title.versionDeviceCounts)
    .filter(([version]) => !listed.has(version))
    .reduce((sum, [, count]) => sum + count, 0);
}

export function JamfPatchDetailPage() {
  const { t } = useLocale();
  const { titleId } = useParams<{ titleId: string }>();

  const [title, setTitle] = useState<JamfPatchTitleDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [versionsExpanded, setVersionsExpanded] = useState(false);

  useEffect(() => {
    if (!titleId) return;

    let cancelled = false;
    setLoading(true);
    setError(null);

    getJamfPatchTitle(titleId)
      .then((response) => {
        if (!cancelled) setTitle(response);
      })
      .catch(() => {
        if (!cancelled) setError(t.jamfPatch.detail.errorLoading);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [titleId, t]);

  return (
    <section className="space-y-6">
      <div>
        <Link to="/devices/applications/jamf-patch" className="text-sm text-muted-foreground hover:underline">
          {t.jamfPatch.detail.back}
        </Link>
      </div>

      {loading && <p className="text-sm text-muted-foreground">{t.jamfPatch.detail.loading}</p>}
      {!loading && error && <p className="text-sm text-destructive">{error}</p>}
      {!loading && !error && !title && <p className="text-sm text-muted-foreground">{t.jamfPatch.detail.notFound}</p>}

      {!loading && !error && title && (
        <>
          <div>
            <p className="text-sm font-medium text-muted-foreground">{t.jamfPatch.eyebrow}</p>
            <h1 className="text-3xl font-bold tracking-tight">{title.name}</h1>
            <p className="mt-1 text-sm text-muted-foreground">
              {title.publisher ?? "—"} · {title.bundleId ?? "—"} · {t.jamfPatch.tableCurrentVersion}:{" "}
              {title.currentVersion}
            </p>
            <p className="mt-1 text-sm text-muted-foreground">
              {t.jamfPatch.detail.deviceSummary(title.deviceCount, title.devicesOnLatest)}
            </p>
          </div>

          <div className="space-y-3 rounded-lg border bg-card p-4">
            <h2 className="text-lg font-semibold">{t.jamfPatch.detail.calendarTitle}</h2>
            <p className="text-sm text-muted-foreground">{t.jamfPatch.detail.calendarDescription}</p>
            <ReleaseCalendar patches={title.patches} />
          </div>

          <div className="space-y-3 rounded-lg border bg-card p-4">
            <h2 className="text-lg font-semibold">{t.jamfPatch.detail.requirementsTitle}</h2>
            <p className="text-sm text-muted-foreground">{t.jamfPatch.detail.requirementsDescription}</p>
            <RequirementsSection groups={title.requirements} />
          </div>

          <div className="space-y-3 rounded-lg border bg-card p-4">
            <h2 className="text-lg font-semibold">{t.jamfPatch.detail.testTitle}</h2>
            <p className="text-sm text-muted-foreground">{t.jamfPatch.detail.testDescription}</p>
            <RequirementsTestPanel requirements={title.requirements} />
          </div>

          <div className="space-y-3 rounded-lg border bg-card p-4">
            <button
              type="button"
              onClick={() => setVersionsExpanded((current) => !current)}
              className="flex w-full items-center gap-2 text-left"
              aria-expanded={versionsExpanded}
            >
              {versionsExpanded ? (
                <ChevronDown className="h-4 w-4 shrink-0 text-muted-foreground" />
              ) : (
                <ChevronRight className="h-4 w-4 shrink-0 text-muted-foreground" />
              )}
              <h2 className="text-lg font-semibold">
                {t.jamfPatch.detail.versionsTitle} ({title.patches.length})
              </h2>
            </button>

            {versionsExpanded && (
              <>
                <div className="overflow-x-auto rounded-lg border bg-card">
                  <table className="w-full text-sm">
                    <thead className="border-b bg-muted/30 text-left text-muted-foreground">
                      <tr>
                        <th className="px-4 py-2 font-medium">{t.jamfPatch.detail.tableVersion}</th>
                        <th className="px-4 py-2 font-medium">{t.jamfPatch.detail.tableReleaseDate}</th>
                        <th className="px-4 py-2 font-medium">{t.jamfPatch.detail.tableDeviceCount}</th>
                        <th className="px-4 py-2 font-medium">
                          <VulnerabilityHeader t={t} />
                        </th>
                      </tr>
                    </thead>
                    <tbody>
                      {title.patches.length === 0 && (
                        <tr>
                          <td className="px-4 py-4 text-muted-foreground" colSpan={4}>
                            {t.jamfPatch.detail.empty}
                          </td>
                        </tr>
                      )}
                      {title.patches.map((patch, index) => (
                        <tr key={`${patch.version}-${index}`} className="border-b last:border-0">
                          <td className="px-4 py-2 font-medium">{patch.version}</td>
                          <td className="px-4 py-2">
                            {patch.releaseDate ? new Date(patch.releaseDate).toLocaleDateString() : "—"}
                          </td>
                          <td className="px-4 py-2 tabular-nums">
                            {title.versionDeviceCounts[patch.version] ?? 0}
                          </td>
                          {/* Stub — requires the LoonSecIO integration to be enabled. */}
                          <td className="px-4 py-2">
                            <VulnerabilityStubCell t={t} />
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>

                <p className="text-sm text-muted-foreground">{t.jamfPatch.detail.versionsTotal(title.patches.length)}</p>
                {unlistedDevices(title) > 0 && (
                  <p className="text-sm text-muted-foreground">{t.jamfPatch.detail.unlistedVersions(unlistedDevices(title))}</p>
                )}
              </>
            )}
          </div>
        </>
      )}
    </section>
  );
}
