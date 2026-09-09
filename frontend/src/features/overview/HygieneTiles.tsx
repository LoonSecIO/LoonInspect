import { useEffect, useRef, useState } from "react";
import { Link } from "react-router";
import { PERMISSIONS } from "@/features/auth/types";
import { useHasPermission } from "@/features/auth/store";
import { listDevices } from "@/features/devices/api";
import { getJamfPatchCoverage } from "@/features/jamfPatch/api";
import { STALE_CHECK_IN_DAYS, coveragePercent, staleCheckInBefore } from "@/features/overview/hygiene";
import { useLocale } from "@/i18n/LocaleContext";

type Counts = {
  stale: number | "failed";
  unmanaged: number | "failed";
  // null when the reader lacks app:read and the tile is not rendered at all.
  coverage: { onLatest: number; total: number } | "failed" | null;
};

/**
 * The hygiene tiles, below the fold (#109). Three fixed-threshold facts, each of which IS
 * a saved search: the tile reads the same `total` the click-through lists. Thresholds are
 * code constants by ruling, never sliders. Zero states are words, never bare numerals.
 *
 * Lazy like its neighbour (#110): nothing is requested until the tiles scroll into view.
 * The coverage tile reads `/api/jamf-patch/coverage`, the posture recorder's own pair
 * definition served live, so the tile and the nightly tape never drift — and the ratio
 * derives here, at render, from both inputs.
 */
export function HygieneTiles() {
  const { t } = useLocale();
  const th = t.overview.hygiene;
  const canReadApps = useHasPermission(PERMISSIONS.APP_READ);
  const sentinel = useRef<HTMLElement>(null);
  const [counts, setCounts] = useState<Counts | null>(null);
  // Fixed at first render so the tile, its link and its label agree on one instant.
  const [staleBefore] = useState(() => staleCheckInBefore(new Date()));

  useEffect(() => {
    const element = sentinel.current;
    if (!element) return;
    let requested = false;
    let cancelled = false;
    const load = () => {
      if (requested) return;
      requested = true;
      const settle = <T,>(promise: Promise<T>): Promise<T | "failed"> => promise.catch(() => "failed" as const);
      Promise.all([
        settle(listDevices({ lastCheckInBefore: staleBefore, pageSize: 1 }).then((r) => r.total)),
        settle(listDevices({ managed: false, pageSize: 1 }).then((r) => r.total)),
        canReadApps
          ? settle(getJamfPatchCoverage().then((c) => ({ onLatest: c.pairsOnLatest, total: c.pairsTotal })))
          : Promise.resolve(null)
      ]).then(([stale, unmanaged, coverage]) => {
        if (!cancelled) setCounts({ stale, unmanaged, coverage });
      });
    };
    if (typeof IntersectionObserver === "undefined") {
      load();
      return () => {
        cancelled = true;
      };
    }
    const observer = new IntersectionObserver((entries) => {
      if (entries.some((entry) => entry.isIntersecting)) {
        load();
        observer.disconnect();
      }
    });
    observer.observe(element);
    return () => {
      cancelled = true;
      observer.disconnect();
    };
  }, [canReadApps, staleBefore]);

  const staleHref = `/devices?${new URLSearchParams({ lastCheckInBefore: staleBefore }).toString()}`;

  return (
    <section ref={sentinel} className="grid gap-3 sm:grid-cols-3">
      <Tile
        title={th.staleTitle(STALE_CHECK_IN_DAYS)}
        href={staleHref}
        body={
          counts === null
            ? t.auth.loading
            : counts.stale === "failed"
              ? th.failed
              : counts.stale === 0
                ? th.staleNone(STALE_CHECK_IN_DAYS)
                : th.staleCount(counts.stale)
        }
        failed={counts?.stale === "failed"}
      />
      <Tile
        title={th.unmanagedTitle}
        href="/devices?managed=false"
        body={
          counts === null
            ? t.auth.loading
            : counts.unmanaged === "failed"
              ? th.failed
              : counts.unmanaged === 0
                ? th.unmanagedNone
                : th.unmanagedCount(counts.unmanaged)
        }
        failed={counts?.unmanaged === "failed"}
      />
      {canReadApps && (
        <Tile
          title={th.coverageTitle}
          href="/devices/applications/jamf-patch"
          body={coverageBody(counts, t.auth.loading, th)}
          failed={counts?.coverage === "failed"}
        />
      )}
    </section>
  );
}

function Tile({ title, href, body, failed }: { title: string; href: string; body: string; failed: boolean }) {
  return (
    <Link to={href} className="block rounded-lg border bg-card px-5 py-4 text-sm shadow-sm hover:bg-accent/40">
      <p className="text-xs font-medium text-muted-foreground">{title}</p>
      <p className={`mt-1 font-semibold ${failed ? "text-destructive" : "text-card-foreground"}`}>{body}</p>
    </Link>
  );
}

function coverageBody(
  counts: Counts | null,
  loading: string,
  th: { failed: string; coverageNone: string; coverageCount: (onLatest: number, total: number, percent: number) => string }
): string {
  if (counts === null) return loading;
  const coverage = counts.coverage;
  if (coverage === null) return "";
  if (coverage === "failed") return th.failed;
  const percent = coveragePercent(coverage.onLatest, coverage.total);
  return percent === null ? th.coverageNone : th.coverageCount(coverage.onLatest, coverage.total, percent);
}
