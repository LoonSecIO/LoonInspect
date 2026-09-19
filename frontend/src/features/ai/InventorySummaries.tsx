import { useEffect, useState } from "react";
import { apiRequest } from "@/config/api";
import { useHasPermission } from "@/features/auth/store";
import { PERMISSIONS } from "@/features/auth/types";

interface Options {
  enabled: boolean;
  provider: string;
  preprompt: string;
  intervalSeconds: number;
}
interface Metrics {
  enabled: boolean;
  provider: string;
  counts: Record<string, number>;
  attempts: number;
  overloadJobs: number;
  averageLatencyMs: number | null;
  dropRate: number | null;
  successRate: number | null;
  oldestQueuedAt: string | null;
  asOf: string;
}
const path = "/inventory-summaries";
const percent = (n: number | null) =>
  n === null ? "—" : `${(n * 100).toFixed(1)}%`;

export function InventorySummarySettings() {
  const canWrite = useHasPermission(PERMISSIONS.SYSTEM_WRITE);
  const [value, setValue] = useState<Options | null>(null);
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    let alive = true;
    apiRequest<Options>(`${path}/settings`)
      .then((v) => {
        if (alive) setValue(v);
      })
      .catch(() => {
        if (alive) setMessage("Could not load inventory summary settings.");
      });
    return () => {
      alive = false;
    };
  }, []);
  const save = () => {
    setBusy(true);
    setMessage("");
    apiRequest<Options>(`${path}/settings`, {
      method: "PUT",
      body: JSON.stringify(value),
    })
      .then((v) => {
        setValue(v);
        setMessage("Inventory summary settings saved.");
      })
      .catch((e: unknown) =>
        setMessage(e instanceof Error ? e.message : "Could not save settings."),
      )
      .finally(() => setBusy(false));
  };
  return (
    <section className="space-y-3 rounded-lg border bg-card p-5">
      <h2 className="text-lg font-semibold">Inventory summaries</h2>
      <p className="text-sm text-muted-foreground">
        Briefings arrive separately from inventory. No changes means “No
        updates” with no AI call. Pending summaries expire after one hour.
      </p>
      <p className="text-sm text-muted-foreground">
        The selected saved endpoint receives app names, versions, finding
        counts, selected posture changes and your instructions. Device identity
        and CVE lists remain in the deterministic SIEM evidence. Enable AI
        consent below before saving an enabled configuration.
      </p>
      {value && (
        <fieldset disabled={!canWrite || busy} className="space-y-3">
          <label className="flex items-center gap-2">
            <input
              type="checkbox"
              checked={value.enabled}
              onChange={(e) =>
                setValue({ ...value, enabled: e.target.checked })
              }
            />{" "}
            Enable inventory summaries
          </label>
          <label className="block">
            Inventory summary provider
            <select
              className="ml-3 rounded border bg-background p-2"
              value={value.provider}
              onChange={(e) => setValue({ ...value, provider: e.target.value })}
            >
              <option value="apple_fm">Apple Foundation Models</option>
              <option value="openai_compatible">OpenAI-compatible</option>
            </select>
          </label>
          <label className="block">
            Customer emphasis / tone
            <textarea
              className="mt-1 block w-full rounded border bg-background p-2"
              maxLength={500}
              rows={3}
              value={value.preprompt}
              onChange={(e) =>
                setValue({ ...value, preprompt: e.target.value })
              }
              placeholder="Emphasize encryption regressions and new critical findings."
            />
          </label>
          <p className="text-xs text-muted-foreground">
            {value.preprompt.length}/500 characters. Instructions cannot
            authorize actions or override evidence, privacy or output limits.
          </p>
          <label className="block">
            Apple FM pause between calls (seconds)
            <input
              className="ml-3 w-20 rounded border bg-background p-2"
              type="number"
              min={1}
              max={60}
              value={value.intervalSeconds}
              onChange={(e) =>
                setValue({ ...value, intervalSeconds: Number(e.target.value) })
              }
            />
          </label>
          <button
            type="button"
            className="rounded bg-primary px-4 py-2 text-primary-foreground"
            onClick={save}
          >
            {busy ? "Saving…" : "Save inventory settings"}
          </button>
        </fieldset>
      )}
      {message && (
        <p role="status" className="text-sm">
          {message}
        </p>
      )}
    </section>
  );
}

export function InventorySummaryMetrics() {
  const allowed = useHasPermission(PERMISSIONS.SYSTEM_READ);
  const [value, setValue] = useState<Metrics | null>(null);
  const [failed, setFailed] = useState(false);
  useEffect(() => {
    if (!allowed) return;
    let alive = true;
    const load = () => {
      apiRequest<Metrics>(`${path}/metrics`)
        .then((v) => {
          if (alive) {
            setValue(v);
            setFailed(false);
          }
        })
        .catch(() => {
          if (alive) setFailed(true);
        });
    };
    load();
    const timer = window.setInterval(load, 15000);
    return () => {
      alive = false;
      window.clearInterval(timer);
    };
  }, [allowed]);
  if (!allowed || (!failed && !value?.enabled)) return null;
  return (
    <section className="space-y-2 rounded-lg border bg-card p-5">
      <h2 className="text-lg font-semibold">
        Inventory AI ·{" "}
        {value?.provider === "apple_fm"
          ? "Apple FM"
          : value?.provider === "openai_compatible"
            ? "OpenAI-compatible"
            : "provider unavailable"}
      </h2>
      {failed ? (
        <p role="status">
          Summary metrics unavailable. Last values may be stale.
        </p>
      ) : (
        <>
          <p className="text-sm text-muted-foreground">
            Last 24 hours · operational measurements, not a capacity benchmark
          </p>
          <div className="grid gap-3 text-sm sm:grid-cols-4">
            <p>
              Successful jobs / attempts{" "}
              <strong className="block">
                {percent(value?.successRate ?? null)}
              </strong>
            </p>
            <p>
              Dropped or failed / received{" "}
              <strong className="block">
                {percent(value?.dropRate ?? null)}
              </strong>
            </p>
            <p>
              Rate-limit responses{" "}
              <strong className="block">{value?.overloadJobs ?? 0}</strong>
            </p>
            <p>
              Mean latest-attempt latency{" "}
              <strong className="block">
                {value?.averageLatencyMs === null
                  ? "—"
                  : `${value?.averageLatencyMs} ms`}
              </strong>
            </p>
          </div>
          <p className="text-sm">
            Queued:{" "}
            {(value?.counts.pending ?? 0) + (value?.counts.processing ?? 0)} ·
            Cache hits: {value?.counts.cached ?? 0} · No updates:{" "}
            {value?.counts.no_updates ?? 0} · Attempts: {value?.attempts ?? 0}
          </p>
          <p className="text-xs text-muted-foreground">
            Oldest queued: {value?.oldestQueuedAt ?? "none"} · As of{" "}
            {value?.asOf}
          </p>
        </>
      )}
    </section>
  );
}
