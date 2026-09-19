import { useEffect, useState } from "react";
import { useHasPermission } from "@/features/auth/store";
import { PERMISSIONS } from "@/features/auth/types";
import { useLocale } from "@/i18n/LocaleContext";
import type { Translations } from "@/i18n/en";
import {
  loadSummarySettings,
  saveSummarySettings,
  loadSummaryMetrics,
} from "./inventorySummaryApi";
import type { SummaryOptions, SummaryMetrics } from "./inventorySummaryApi";

type Copy = Translations["ai"]["inventorySummary"];

export function InventorySummaryFields({
  value,
  setValue,
  canWrite,
  busy,
  save,
  copy,
}: {
  value: SummaryOptions;
  setValue: (value: SummaryOptions) => void;
  canWrite: boolean;
  busy: boolean;
  save: () => void;
  copy: Copy;
}) {
  return (
    <fieldset disabled={!canWrite || busy} className="space-y-3">
      <label className="flex items-center gap-2">
        <input
          type="checkbox"
          checked={value.enabled}
          onChange={(e) => setValue({ ...value, enabled: e.target.checked })}
        />
        {copy.enable}
      </label>
      <label className="block">
        {copy.provider}
        <select
          className="ml-3 rounded border bg-background p-2"
          value={value.provider}
          onChange={(e) => setValue({ ...value, provider: e.target.value })}
        >
          <option value="apple_fm">Apple Foundation Models</option>
          <option value="openai_compatible">{copy.compatible}</option>
        </select>
      </label>
      <label className="block">
        {copy.preference}
        <textarea
          className="mt-1 block w-full rounded border bg-background p-2"
          maxLength={500}
          rows={3}
          value={value.preprompt}
          onChange={(e) => setValue({ ...value, preprompt: e.target.value })}
          placeholder={copy.placeholder}
        />
      </label>
      <p className="text-xs text-muted-foreground">
        {value.preprompt.length}
        {copy.preferenceHelp}
      </p>
      <label className="block">
        {copy.pause}
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
        {busy ? copy.saving : copy.save}
      </button>
    </fieldset>
  );
}

export function InventorySummarySettings() {
  const { t } = useLocale();
  const copy = t.ai.inventorySummary;
  const canWrite = useHasPermission(PERMISSIONS.SYSTEM_WRITE);
  const [value, setValue] = useState<SummaryOptions | null>(null);
  const [status, setStatus] = useState<
    "" | "loadError" | "saveError" | "saved"
  >("");
  const [detail, setDetail] = useState("");
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    let alive = true;
    loadSummarySettings()
      .then((v) => {
        if (alive) setValue(v);
      })
      .catch(() => {
        if (alive) setStatus("loadError");
      });
    return () => {
      alive = false;
    };
  }, []);
  const save = () => {
    if (!value) return;
    setBusy(true);
    setStatus("");
    setDetail("");
    saveSummarySettings(value)
      .then((v) => {
        setValue(v);
        setStatus("saved");
      })
      .catch((e: unknown) => {
        setStatus("saveError");
        if (e instanceof Error) setDetail(e.message);
      })
      .finally(() => setBusy(false));
  };
  return (
    <section className="space-y-3 rounded-lg border bg-card p-5">
      <h2 className="text-lg font-semibold">{copy.title}</h2>
      <p className="text-sm text-muted-foreground">{copy.description}</p>
      <p className="text-sm text-muted-foreground">{copy.disclosure}</p>
      {value && (
        <InventorySummaryFields
          value={value}
          setValue={setValue}
          canWrite={canWrite}
          busy={busy}
          save={save}
          copy={copy}
        />
      )}
      {status && (
        <p role="status" className="text-sm">
          {copy[status]} {detail}
        </p>
      )}
    </section>
  );
}

export function InventorySummaryMetricsView({
  value,
  failed,
  copy,
  locale,
}: {
  value: SummaryMetrics | null;
  failed: boolean;
  copy: Copy;
  locale: string;
}) {
  const percent = (n: number | null | undefined) =>
    n == null
      ? "—"
      : new Intl.NumberFormat(locale, {
          style: "percent",
          maximumFractionDigits: 1,
        }).format(n);
  const stamp = (date: string | null | undefined) =>
    date ? new Date(date).toLocaleString(locale) : copy.none;
  return (
    <section className="space-y-2 rounded-lg border bg-card p-5">
      <h2 className="text-lg font-semibold">
        {copy.metricsTitle} ·{" "}
        {value?.provider === "apple_fm"
          ? "Apple FM"
          : value?.provider === "openai_compatible"
            ? copy.compatible
            : copy.providerUnavailable}
      </h2>
      {failed ? (
        <p role="status">{copy.unavailable}</p>
      ) : (
        <>
          <p className="text-sm text-muted-foreground">{copy.window}</p>
          <div className="grid gap-3 text-sm sm:grid-cols-4">
            <p>
              {copy.success}
              <strong className="block">{percent(value?.successRate)}</strong>
            </p>
            <p>
              {copy.dropped}
              <strong className="block">{percent(value?.dropRate)}</strong>
            </p>
            <p>
              {copy.overloads}
              <strong className="block">{value?.overloadJobs ?? 0}</strong>
            </p>
            <p>
              {copy.latency}
              <strong className="block">
                {value?.averageLatencyMs == null
                  ? "—"
                  : `${value.averageLatencyMs} ms`}
              </strong>
            </p>
          </div>
          <p className="text-sm">
            {copy.queued}:{" "}
            {(value?.counts.pending ?? 0) + (value?.counts.processing ?? 0)} ·{" "}
            {copy.cached}: {value?.counts.cached ?? 0} · {copy.noUpdates}:{" "}
            {value?.counts.no_updates ?? 0} · {copy.attempts}:{" "}
            {value?.attempts ?? 0}
          </p>
          <p className="text-xs text-muted-foreground">
            {copy.oldest}: {stamp(value?.oldestQueuedAt)} · {copy.asOf}:{" "}
            {stamp(value?.asOf)}
          </p>
          {!!value?.reasons.length && (
            <details>
              <summary>{copy.diagnostics}</summary>
              <ul className="space-y-2 text-sm">
                {value.reasons.map((r) => (
                  <li key={r.reason}>
                    {r.reason}: {r.count} — {r.nextCheck}
                  </li>
                ))}
              </ul>
            </details>
          )}
        </>
      )}
    </section>
  );
}

export function InventorySummaryMetrics() {
  const { t, locale } = useLocale();
  const allowed = useHasPermission(PERMISSIONS.SYSTEM_READ);
  const [value, setValue] = useState<SummaryMetrics | null>(null);
  const [failed, setFailed] = useState(false);
  useEffect(() => {
    if (!allowed) return;
    let alive = true;
    const load = () => {
      loadSummaryMetrics()
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
    <InventorySummaryMetricsView
      value={value}
      failed={failed}
      copy={t.ai.inventorySummary}
      locale={locale}
    />
  );
}
