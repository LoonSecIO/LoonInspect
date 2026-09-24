import { useEffect, useState } from "react";
import { Link } from "react-router";
import { useAuthStore } from "@/features/auth/store";
import { useLocale } from "@/i18n/LocaleContext";
import {
  changedValue,
  formatHistoryValue,
  loadHistory,
  loadHistoryPoint,
  saveHistorySlots,
  type HistoryDetail,
  type HistoryPage,
} from "./history";

/** A keyed instance drops every request and saved value when the account, tenant or device changes. */
export function DeviceHistoryCard({ deviceId }: { deviceId: number }) {
  const user = useAuthStore((s) => s.user);
  const scope = `${user?.tenant?.id}:${user?.id}:${deviceId}`;
  return user?.tenant ? <HistoryCard key={scope} deviceId={deviceId} /> : null;
}

function HistoryCard({ deviceId }: { deviceId: number }) {
  const { t, locale } = useLocale();
  const copy = t.deviceHistory;
  const [page, setPage] = useState(1);
  const [selection, setSelection] = useState<string | null>(null);
  const [revision, setRevision] = useState(0);
  const [timeline, setTimeline] = useState<{
    page: number;
    value?: HistoryPage;
    error?: boolean;
  } | null>(null);
  const [loaded, setLoaded] = useState<{
    key: string;
    value?: HistoryDetail;
    error?: boolean;
  } | null>(null);
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState<string[]>([]);
  const [search, setSearch] = useState("");
  const [replaceKey, setReplaceKey] = useState("");
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState(false);
  const [retry, setRetry] = useState(0);

  useEffect(() => {
    let cancelled = false;
    loadHistory(deviceId, page)
      .then((value) => {
        if (!cancelled) setTimeline({ page, value });
      })
      .catch(() => {
        if (!cancelled) setTimeline({ page, error: true });
      });
    return () => {
      cancelled = true;
    };
  }, [deviceId, page, retry]);
  const list = timeline?.page === page ? timeline : null;
  const selected =
    selection && list?.value?.items.some((p) => p.id === selection)
      ? selection
      : (list?.value?.items[0]?.id ?? null);
  const requestKey = `${selected}:${revision}:${retry}`;
  useEffect(() => {
    if (!selected) return;
    let cancelled = false;
    loadHistoryPoint(deviceId, selected)
      .then((value) => {
        if (!cancelled) setLoaded({ key: requestKey, value });
      })
      .catch(() => {
        if (!cancelled) setLoaded({ key: requestKey, error: true });
      });
    return () => {
      cancelled = true;
    };
  }, [deviceId, selected, requestKey]);
  const result = loaded?.key === requestKey ? loaded : null;
  const detail = result?.value;
  const latest = page === 1 && selected === list?.value?.items[0]?.id;
  const date = (value: string) => new Date(value).toLocaleString(locale);
  const valueText = (v: { state: string; value: unknown; key?: string }) =>
    v.key === "observation.lastCheckIn" &&
    v.state === "present" &&
    typeof v.value === "string"
      ? date(v.value)
      : formatHistoryValue(v, copy.states, copy.yes, copy.no);
  const label = (v: {
    key: string;
    label: string;
    section: string;
    field: string;
  }) =>
    copy.defaults[v.key] ??
    (t.changes.sections[v.section] ?? v.section) + " · " + v.label;
  const save = async () => {
    if (!selected || saving) return;
    setSaving(true);
    setSaveError(false);
    try {
      await saveHistorySlots(deviceId, selected, draft);
      setEditing(false);
      setRevision((r) => r + 1);
    } catch {
      setSaveError(true);
    } finally {
      setSaving(false);
    }
  };
  const changes = detail?.values.filter((v) => changedValue(v, v.before)) ?? [];
  const available =
    detail?.choices.filter(
      (c) =>
        c.enabled &&
        !draft.includes(c.key) &&
        `${label(c)} ${Object.values(c.identity ?? {}).join(" ")} ${c.sample ? valueText({ ...c.sample, key: c.key }) : ""}`
          .toLowerCase()
          .includes(search.toLowerCase()),
    ) ?? [];
  const selectValue = (key: string) => {
    setDraft((d) =>
      replaceKey
        ? d.map((existing) => (existing === replaceKey ? key : existing))
        : d.length < 20
          ? [...d, key]
          : d,
    );
    setReplaceKey("");
  };
  const summary = detail?.summary;
  const summaryText =
    summary && (summary.status === "completed" || summary.status === "cached")
      ? summary.text
      : null;
  const error = list?.error || result?.error;
  const choose = (id: string) => {
    setSelection(id);
    setRevision((r) => r + 1);
    setEditing(false);
  };

  return (
    <section
      className="overflow-hidden rounded-lg border bg-card"
      aria-label={copy.heading}
    >
      <header className="flex flex-wrap items-center justify-between gap-3 border-b bg-muted/30 px-5 py-4">
        <div>
          <p className="font-mono text-xs uppercase tracking-widest text-muted-foreground">
            {copy.eyebrow}
          </p>
          <h2 className="mt-1 text-xl font-semibold">{copy.heading}</h2>
        </div>
        <div className="flex items-center gap-3">
          {detail && (
            <span
              className={`rounded border px-2 py-1 font-mono text-xs uppercase tracking-wider ${latest ? "text-primary" : "text-muted-foreground"}`}
            >
              {latest ? copy.latest : copy.historical}
            </span>
          )}
          <button
            type="button"
            className="text-sm underline underline-offset-4 disabled:opacity-50"
            disabled={!detail || saving}
            onClick={() => {
              setDraft(detail?.values.map((v) => v.key) ?? []);
              setEditing(!editing);
              setSearch("");
              setReplaceKey("");
              setSaveError(false);
            }}
          >
            {editing ? copy.cancel : copy.customize}
          </button>
        </div>
      </header>
      <div className="space-y-5 p-5">
        {error ? (
          <div role="alert" className="text-sm text-destructive">
            {copy.error}{" "}
            <button
              type="button"
              className="underline"
              onClick={() => {
                setTimeline(null);
                setLoaded(null);
                setRetry((r) => r + 1);
              }}
            >
              {copy.retry}
            </button>
          </div>
        ) : !list?.value ? (
          <p role="status" className="text-sm text-muted-foreground">
            {copy.loading}
          </p>
        ) : list.value.items.length === 0 ? (
          <p className="text-sm text-muted-foreground">{copy.empty}</p>
        ) : (
          <>
            {/* The line below reads oldest to newest, left to right, so the control on the
                left pages toward older states and the one on the right toward newer (#618). */}
            <div className="flex items-center justify-between gap-3 text-xs text-muted-foreground">
              <button
                type="button"
                disabled={!list.value.hasMore || saving}
                className="underline disabled:opacity-40"
                onClick={() => {
                  setTimeline(null);
                  setRevision((r) => r + 1);
                  setPage((p) => p + 1);
                  setSelection(null);
                  setEditing(false);
                }}
              >
                {copy.older}
              </button>
              <span>{copy.recordedStates}</span>
              <button
                type="button"
                disabled={page === 1 || saving}
                className="underline disabled:opacity-40"
                onClick={() => {
                  setTimeline(null);
                  setRevision((r) => r + 1);
                  setPage((p) => p - 1);
                  setSelection(null);
                  setEditing(false);
                }}
              >
                {copy.newer}
              </button>
            </div>
            <ol
              className="flex overflow-x-auto pb-2"
              aria-label={copy.timeline}
            >
              {[...list.value.items].reverse().map((p) => (
                <li
                  key={p.id}
                  className="relative min-w-20 flex-1 before:absolute before:left-0 before:right-0 before:top-3 before:h-px before:bg-border"
                >
                  <button
                    type="button"
                    disabled={saving}
                    className="relative flex w-full flex-col items-center gap-2 px-2 text-xs"
                    aria-pressed={selected === p.id}
                    aria-label={`${copy.observed}: ${date(p.observedAt)} · ${p.kind === "assessment" ? copy.evaluated : copy.collected}: ${date(p.collectedAt)}`}
                    title={`${copy.observed}: ${date(p.observedAt)} · ${p.kind === "assessment" ? copy.evaluated : copy.collected}: ${date(p.collectedAt)}`}
                    onClick={() => choose(p.id)}
                  >
                    <span
                      className={`z-10 block h-6 w-6 rounded-full border-2 ${selected === p.id ? "border-primary bg-primary" : "border-muted-foreground bg-card"}`}
                    />
                    <span className="whitespace-nowrap font-mono text-muted-foreground">
                      {new Date(p.kind === "assessment" ? p.collectedAt : p.observedAt).toLocaleDateString(locale, {
                        month: "short",
                        day: "numeric",
                      })}
                    </span>
                    {p.kind === "assessment" && <span>{copy.evaluated}</span>}
                  </button>
                </li>
              ))}
            </ol>
            {!detail ? (
              <p role="status" className="text-sm text-muted-foreground">
                {copy.loading}
              </p>
            ) : (
              <>
                <div className="flex flex-wrap justify-between gap-1 border-b pb-3 text-xs text-muted-foreground">
                  <span>
                    {copy.observed}:{" "}
                    <time dateTime={detail.observedAt}>
                      {date(detail.observedAt)}
                    </time>
                  </span>
                  <span>
                    {detail.kind === "assessment" ? copy.evaluated : copy.collected}: {date(detail.collectedAt)}
                  </span>
                </div>
                {detail.kind === "assessment" && (
                  <p className="text-sm text-muted-foreground">{copy.assessmentOnly}</p>
                )}
                {editing ? (
                  <div className="space-y-3 rounded border border-dashed p-4">
                    <p className="text-sm">{copy.personal}</p>
                    <p className="text-xs text-muted-foreground">
                      {copy.policy}
                    </p>
                    <ul className="space-y-2">
                      {draft.map((key) => {
                        const choice =
                          detail.choices.find((c) => c.key === key) ??
                          detail.values.find((c) => c.key === key);
                        return (
                          <li
                            key={key}
                            className="flex items-center justify-between gap-3 text-sm"
                          >
                            <span>{choice ? label(choice) : key}</span>
                            <button
                              type="button"
                              disabled={saving}
                              className="underline"
                              onClick={() => {
                                setDraft((d) => d.filter((k) => k !== key));
                                if (replaceKey === key) setReplaceKey("");
                              }}
                            >
                              {copy.remove}
                            </button>
                          </li>
                        );
                      })}
                    </ul>
                    <label className="block text-sm">
                      {copy.add}{" "}
                      <span className="text-muted-foreground">
                        ({draft.length}/20)
                      </span>
                      <input
                        type="search"
                        value={search}
                        onChange={(e) => setSearch(e.target.value)}
                        placeholder={copy.search}
                        className="mt-2 w-full rounded border bg-background px-3 py-2"
                        disabled={saving}
                      />
                    </label>
                    <label className="block text-sm">
                      {copy.addOrReplace}
                      <select
                        className="ml-2 max-w-full rounded border bg-background p-2"
                        value={replaceKey}
                        disabled={saving}
                        onChange={(event) => setReplaceKey(event.target.value)}
                      >
                        <option value="">{copy.add}</option>
                        {draft.map((key) => {
                          const choice =
                            detail.choices.find((c) => c.key === key) ??
                            detail.values.find((c) => c.key === key);
                          return (
                            <option key={key} value={key}>
                              {copy.replace} {choice ? label(choice) : key}
                            </option>
                          );
                        })}
                      </select>
                    </label>
                    {draft.length >= 20 && !replaceKey && (
                      <p
                        role="status"
                        className="text-sm text-muted-foreground"
                      >
                        {copy.atLimit}
                      </p>
                    )}
                    {available.some(
                      (c) => c.section !== "extension_attributes",
                    ) && (
                      <ul className="max-h-52 overflow-y-auto rounded border">
                        {available
                          .filter((c) => c.section !== "extension_attributes")
                          .map((c) => (
                            <li key={c.key}>
                              <button
                                type="button"
                                disabled={
                                  saving || (draft.length >= 20 && !replaceKey)
                                }
                                className="w-full px-3 py-2 text-left text-sm hover:bg-muted disabled:opacity-50"
                                onClick={() => selectValue(c.key)}
                              >
                                {label(c)}
                                {c.identity?.definitionId !== undefined && (
                                  <span className="ml-2 font-mono text-xs text-muted-foreground">
                                    ID {String(c.identity.definitionId)}
                                  </span>
                                )}
                                {c.sample && (
                                  <span className="block text-xs text-muted-foreground">
                                    {valueText({ ...c.sample, key: c.key })}
                                  </span>
                                )}
                              </button>
                            </li>
                          ))}
                      </ul>
                    )}
                    {available.some(
                      (c) => c.section === "extension_attributes",
                    ) && (
                      <div className="max-h-52 overflow-auto rounded border">
                        <table
                          className="w-full text-left text-sm"
                          aria-label={t.changes.sections.extension_attributes}
                        >
                          <thead className="bg-muted/40">
                            <tr>
                              <th className="px-3 py-2">
                                {copy.attributeName}
                              </th>
                              <th className="px-3 py-2">{copy.attributeId}</th>
                              <th className="px-3 py-2">
                                {copy.attributeValue}
                              </th>
                              <th className="px-3 py-2">
                                <span className="sr-only">
                                  {copy.addOrReplace}
                                </span>
                              </th>
                            </tr>
                          </thead>
                          <tbody>
                            {available
                              .filter(
                                (c) => c.section === "extension_attributes",
                              )
                              .map((c) => (
                                <tr key={c.key} className="border-t">
                                  <td className="px-3 py-2">
                                    {c.name ?? c.label}
                                  </td>
                                  <td className="px-3 py-2 font-mono">
                                    {String(c.identity?.definitionId ?? "—")}
                                  </td>
                                  <td className="px-3 py-2">
                                    {c.sample ? valueText(c.sample) : "—"}
                                  </td>
                                  <td className="px-3 py-2">
                                    <button
                                      type="button"
                                      className="underline disabled:opacity-50"
                                      disabled={
                                        saving ||
                                        (draft.length >= 20 && !replaceKey)
                                      }
                                      aria-label={`${replaceKey ? copy.replace : copy.add} ${c.name ?? c.label}`}
                                      onClick={() => selectValue(c.key)}
                                    >
                                      {replaceKey ? copy.replace : copy.add}
                                    </button>
                                  </td>
                                </tr>
                              ))}
                          </tbody>
                        </table>
                      </div>
                    )}
                    {available.length === 0 && (
                      <p
                        role="status"
                        className="text-sm text-muted-foreground"
                      >
                        {copy.noMatches}
                      </p>
                    )}
                    {saveError && (
                      <p role="alert" className="text-sm text-destructive">
                        {copy.saveError}
                      </p>
                    )}
                    <div className="flex gap-3">
                      <button
                        type="button"
                        disabled={saving}
                        onClick={() => void save()}
                        className="rounded bg-primary px-4 py-2 text-sm text-primary-foreground disabled:opacity-50"
                      >
                        {saving ? copy.saving : copy.save}
                      </button>
                      <button
                        type="button"
                        disabled={saving}
                        onClick={() => setEditing(false)}
                        className="text-sm underline"
                      >
                        {copy.cancel}
                      </button>
                    </div>
                  </div>
                ) : (
                  <dl className="divide-y">
                    {detail.values.map((v) => (
                      <div
                        key={v.key}
                        className="flex flex-wrap items-baseline justify-between gap-x-5 gap-y-1 py-3 first:pt-0"
                      >
                        <dt className="font-mono text-xs uppercase tracking-wider text-muted-foreground">
                          {label(v)}
                        </dt>
                        <dd className="max-w-full break-words text-right text-sm font-semibold tabular-nums">
                          {valueText(v)}
                          {changedValue(v, v.before) && (
                            <span className="ml-2 font-normal text-muted-foreground">
                              ← {valueText(v.before!)}
                            </span>
                          )}
                        </dd>
                      </div>
                    ))}
                    {detail.values.length < 20 && (
                      <div className="pt-3">
                        <button
                          type="button"
                          className="text-sm underline"
                          onClick={() => {
                            setDraft(detail.values.map((v) => v.key));
                            setSearch("");
                            setReplaceKey("");
                            setSaveError(false);
                            setEditing(true);
                          }}
                        >
                          {copy.add}
                        </button>
                      </div>
                    )}
                  </dl>
                )}
                {detail.assessment?.vulnerabilityEvidence && (
                  <details className="rounded border p-3 text-xs">
                    <summary className="cursor-pointer">{copy.assessmentEvidence}</summary>
                    <p className="my-2 break-all font-mono">
                      {copy.release}: {detail.assessment.vulnerabilityEvidence.releaseDigest}
                    </p>
                    <ul className="space-y-2">
                      {detail.assessment.vulnerabilityEvidence.builds.map((build) => (
                        <li key={build.keyFull}>
                          <span className="font-medium">{build.name} · {build.version}</span>
                          {" · "}{build.counts ? copy.findingCount(build.counts.total) : copy.unknownBuild}
                          {build.idsTruncated && <> · {copy.incompleteIds}</>}
                          {" · "}{copy.evaluated}: {build.evaluatedAt ? date(build.evaluatedAt) : copy.states.not_recorded}
                          {build.ids?.length ? <p className="mt-1 break-words font-mono">{build.ids.join(", ")}</p> : null}
                        </li>
                      ))}
                    </ul>
                  </details>
                )}
                {detail.values.some((v) => v.key.startsWith("findings.")) && (
                  <p className="text-xs text-muted-foreground">
                    {detail.assessment
                      ? copy.coverage(
                          detail.assessment.covered,
                          detail.assessment.outside,
                          detail.assessment.corpus.join(", ") ||
                            copy.states.not_recorded,
                        )
                      : copy.noAssessment}
                  </p>
                )}
                <div className="space-y-2 rounded-lg border border-dashed border-primary/50 bg-primary/5 p-4">
                  <h3 className="font-mono text-xs font-semibold uppercase tracking-wider text-primary">
                    {copy.whatMoved}
                  </h3>
                  {detail.baseline ? (
                    <p className="text-sm">{copy.baseline}</p>
                  ) : changes.length ? (
                    <ul className="space-y-1 text-sm">
                      {changes.map((v) => (
                        <li key={v.key}>
                          {label(v)}: {valueText(v.before!)} → {valueText(v)}
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <p className="text-sm text-muted-foreground">
                      {copy.noSelectedChanges}
                    </p>
                  )}
                  {summaryText ? (
                    <>
                      <p className="pt-2 text-sm">{summaryText}</p>
                      <p className="text-xs text-muted-foreground">
                        {copy.advisory} ·{" "}
                        {summary?.provider === "apple_fm"
                          ? "Apple FM"
                          : "OpenAI-compatible"}
                      </p>
                    </>
                  ) : detail.kind !== "assessment" ? (
                    <p className="text-xs text-muted-foreground">
                      {copy.summaries[summary?.status ?? "unavailable"] ??
                        copy.summaries.unavailable}
                    </p>
                  ) : null}
                  <Link
                    className="inline-block text-xs underline underline-offset-4"
                    to={`/devices/changes?${new URLSearchParams({ spanId: detail.spanId })}`}
                  >
                    {copy.evidence}
                  </Link>
                </div>
              </>
            )}
          </>
        )}
      </div>
    </section>
  );
}
