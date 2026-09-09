import { useEffect, useRef, useState } from "react";
import { Link } from "react-router";
import { PERMISSIONS } from "@/features/auth/types";
import { useHasPermission } from "@/features/auth/store";
import { listJamfPatchTitles } from "@/features/jamfPatch/api";
import type { JamfPatchTitle } from "@/features/jamfPatch/types";
import { rankLaggards } from "@/features/overview/patchLaggards";
import { useLocale } from "@/i18n/LocaleContext";

type Loaded = { status: "loaded"; rows: JamfPatchTitle[]; total: number } | { status: "failed" } | null;

/**
 * Patch laggards, lazily (#110) — the top five Jamf Patch titles by devices behind,
 * below the fold of the Overview.
 *
 * **The blessed cache-don't-calculate exception, founder-ruled.** The per-title counts
 * are read-time joins through the match tables; one `/api/jamf-patch/titles` call pulls
 * the whole catalog with them and the ranking happens here. That is fine at launch scale
 * and wrong at the 40k design target, and it is allowed *because* it is scoped, below the
 * fold, and lazy: nothing here is requested until the tile scrolls into view, so it never
 * blocks first paint. The expiry is named, and carried by the issue's tech-debt label: a
 * stored per-title rollup replaces the scan when any tenant approaches the design
 * target (KNOWN_ISSUES.md §7).
 *
 * This table is also the designated slot where a KEV column lights up in place when the
 * LoonVD wire ships. No vulnerability pixels before then.
 */
export function PatchLaggardsTile() {
  const { t } = useLocale();
  const tl = t.overview.laggards;
  const canRead = useHasPermission(PERMISSIONS.APP_READ);
  const sentinel = useRef<HTMLElement>(null);
  const [state, setState] = useState<Loaded>(null);

  // Nothing is fetched until the tile is on screen: the observer's callback is where the
  // request starts and where state is set, so first paint owes this tile nothing.
  useEffect(() => {
    if (!canRead) return;
    const element = sentinel.current;
    if (!element) return;
    let requested = false;
    let cancelled = false;
    const load = () => {
      if (requested) return;
      requested = true;
      listJamfPatchTitles()
        .then((response) => {
          if (cancelled) return;
          setState({ status: "loaded", rows: rankLaggards(response.items), total: response.total });
        })
        .catch(() => {
          // #150's rule: failure must never read as emptiness.
          if (!cancelled) setState({ status: "failed" });
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
  }, [canRead]);

  if (!canRead) return null;

  return (
    <section ref={sentinel} className="rounded-lg border bg-card px-5 py-4 text-sm shadow-sm">
      <div className="flex items-baseline justify-between gap-3">
        <h2 className="font-semibold text-card-foreground">{tl.title}</h2>
        <Link to="/devices/applications/jamf-patch" className="text-xs text-muted-foreground hover:underline">
          {tl.all}
        </Link>
      </div>
      <p className="mt-1 text-xs text-muted-foreground">{tl.help}</p>
      {state === null && <p className="mt-3 text-muted-foreground">{t.auth.loading}</p>}
      {state?.status === "failed" && <p className="mt-3 text-destructive">{tl.failed}</p>}
      {state?.status === "loaded" && state.total === 0 && <p className="mt-3 text-muted-foreground">{tl.noCatalog}</p>}
      {state?.status === "loaded" && state.total > 0 && state.rows.length === 0 && (
        <p className="mt-3 text-muted-foreground">{tl.nobodyBehind}</p>
      )}
      {state?.status === "loaded" && state.rows.length > 0 && (
        <ol className="mt-3 divide-y">
          {state.rows.map((title) => (
            <li key={title.id}>
              <Link
                to={`/devices/applications/jamf-patch/${encodeURIComponent(title.id)}`}
                className="flex flex-wrap items-baseline justify-between gap-x-3 gap-y-0.5 py-2 hover:underline"
              >
                <span className="font-medium">{title.name}</span>
                <span className="text-xs text-muted-foreground">
                  {tl.row(title.devicesBehind, title.deviceCount, title.devicesOnLatest, title.currentVersion)}
                </span>
              </Link>
            </li>
          ))}
        </ol>
      )}
    </section>
  );
}
