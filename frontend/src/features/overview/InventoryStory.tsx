import { useCallback, useEffect, useRef, useState } from "react";
import type { ReactNode } from "react";
import { Link } from "react-router";
import { listCatalog } from "@/features/catalog/api";
import type { CatalogSummary } from "@/features/catalog/types";
import { listDevices } from "@/features/devices/api";
import { listApplications } from "@/features/devices/applicationsApi";
import type { Application } from "@/features/devices/applicationsApi";
import { AsOfStamp } from "@/features/overview/AsOfStamp";
import { HygieneTiles } from "@/features/overview/HygieneTiles";
import type { InventoryTile } from "@/features/overview/overviewPlan";
import { useLocale } from "@/i18n/LocaleContext";

/** How many apps the prevalence tile names. */
const TOP_APPS = 5;

/** The board re-reads itself on this cadence. The stamp, not the interval, is what an
 *  operator trusts: when a refresh stops landing, every age goes on climbing. */
const REFRESH_MS = 300_000;

type Cell<T> = T | "failed";
type Words = { loading: string; failed: string };

interface Cells {
  /** When this batch landed — what every tile is stamped with. */
  readAt: string;
  fleet: Cell<number> | null;
  catalog: Cell<CatalogSummary> | null;
  topApps: Cell<Application[]> | null;
}

/**
 * The inventory-read story on `/` (#115, re-scoped by Kyle 2026-09-16): the front page of
 * an account without `destination:read` is this board rather than the sentence it used to
 * be. Which tiles it holds, and why that predicate, is `planOverview`'s — decided there.
 *
 * **Two lines this board does not cross**, both from #117. *Needs Attention is never
 * recomposed here*: no failure count, no health dot, no "3 things to look at" — there is
 * exactly one composition of that answer (`needsAttention.ts`, `docs/v-never.md`), and
 * everything below counts things rather than judging them. *Every tile ages visibly*, via
 * `AsOfStamp`, so a dead refresh cannot read as calm on the surface this board unblocks:
 * a viewer session left running on a wall display.
 */
export function InventoryStory({ tiles }: { tiles: readonly InventoryTile[] }) {
  const { t } = useLocale();
  const ti = t.overview.inventory;
  const words = { loading: t.auth.loading, failed: ti.failed };
  const [cells, setCells] = useState<Cells | null>(null);
  const mounted = useRef(true);

  const load = useCallback(() => {
    const settle = <T,>(promise: Promise<T>): Promise<Cell<T>> => promise.catch(() => "failed" as const);
    const ask = <T,>(tile: InventoryTile, read: () => Promise<T>): Promise<Cell<T> | null> =>
      tiles.includes(tile) ? settle(read()) : Promise.resolve(null);

    void Promise.all([
      ask("fleet", () => listDevices({ pageSize: 1 }).then((page) => page.total)),
      // An answer carrying no summary is an `appHash`-scoped read (#299), which this is
      // not: read it as a refusal. A null cell would say "Loading…" here for ever.
      ask("catalog", () => listCatalog({ pageSize: 1 }).then((page) => page.summary ?? ("failed" as const))),
      ask("topApps", () => listApplications({ pageSize: TOP_APPS }).then((page) => page.items))
    ]).then(([fleet, catalog, topApps]) => {
      if (mounted.current) setCells({ readAt: new Date().toISOString(), fleet, catalog, topApps });
    });
  }, [tiles]);

  useEffect(() => {
    mounted.current = true;
    load();
    const handle = window.setInterval(() => {
      if (!document.hidden) load();
    }, REFRESH_MS);
    return () => {
      mounted.current = false;
      window.clearInterval(handle);
    };
  }, [load]);

  const readAt = cells?.readAt ?? null;

  const card = (tile: InventoryTile): ReactNode => {
    switch (tile) {
      // Full width, like the hygiene row: a lone half tile leaves a hole beside the count.
      case "fleet":
        return (
          <div key={tile} className="sm:col-span-2">
            <Tile title={ti.fleetTitle} href="/devices" asOf={readAt}>
              {resolve(cells?.fleet, words, (n) => (n === 0 ? ti.fleetNone : ti.fleetCount(n)))}
            </Tile>
          </div>
        );
      // The hygiene counts (#109), reused rather than restated: one pod, one set of numbers.
      case "hygiene":
        return (
          <div key={tile} className="sm:col-span-2">
            <HygieneTiles />
          </div>
        );
      case "catalog":
        return (
          <Tile key={tile} title={ti.catalogTitle} href="/devices/applications/catalog" asOf={readAt}>
            {resolve(cells?.catalog, words, (s) =>
              s.entries === 0 ? ti.catalogNone : ti.catalogCounts(s.entries, s.matched, s.unmatched)
            )}
          </Tile>
        );
      case "topApps":
        return (
          <Tile key={tile} title={ti.topAppsTitle} href="/devices/applications" asOf={readAt}>
            {resolve(cells?.topApps, words, (rows) =>
              rows.length === 0 ? (
                ti.topAppsNone
              ) : (
                <ul className="space-y-1 font-normal">
                  {rows.map((app) => (
                    <li key={app.appHash}>{ti.topAppsRow(app.name, app.deviceCount)}</li>
                  ))}
                </ul>
              )
            )}
          </Tile>
        );
    }
  };

  return (
    <section className="space-y-6">
      <div className="space-y-2">
        <p className="text-sm font-medium text-muted-foreground">{t.overview.eyebrow}</p>
        <h1 className="text-3xl font-bold tracking-tight">{t.overview.title}</h1>
        {/* Said once, at the top, rather than as a denied segment inside every tile: this
            board IS the disclosure that the pipeline half is not this account's to see. */}
        <p className="max-w-2xl text-muted-foreground">{tiles.length === 0 ? ti.nothing : ti.intro}</p>
      </div>
      <div className="grid gap-3 sm:grid-cols-2">{tiles.map(card)}</div>
    </section>
  );
}

/** Loading, refused, or answered — the three states every tile here has, resolved in one
 *  place so no tile can collapse "could not load" into "nothing to report" (#150). */
function resolve<T>(cell: Cell<T> | null | undefined, words: Words, render: (value: T) => ReactNode): ReactNode {
  if (cell === null || cell === undefined) return words.loading;
  if (cell === "failed") return words.failed;
  // Narrowed by the line above; TypeScript cannot prove it while `T` is open.
  return render(cell as T);
}

/** A claim, a body, the stamp that ages it, and the link: every tile here IS a saved search. */
function Tile(props: { title: string; href: string; asOf: string | null; children: ReactNode }) {
  return (
    <Link to={props.href} className="block rounded-lg border bg-card px-5 py-4 text-sm shadow-sm hover:bg-accent/40">
      <p className="text-xs font-medium text-muted-foreground">{props.title}</p>
      <div className="mt-1 font-semibold text-card-foreground">{props.children}</div>
      <AsOfStamp asOf={props.asOf} />
    </Link>
  );
}
