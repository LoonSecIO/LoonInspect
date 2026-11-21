import { useEffect, useState } from "react";
import { Link } from "react-router";
import { apiRequest } from "@/config/api";
import { useAuthStore } from "@/features/auth/store";
import { useLocale } from "@/i18n/LocaleContext";

type Mac = {
  id: number;
  name: string;
  version: string | null;
  build: string | null;
  model: string | null;
  observed: string;
  latest: string | null;
  patch: string;
  eligibility: string;
};
type Report = {
  asOf: string | null;
  targets: string[];
  target: string;
  devices: Mac[];
  total: number;
  eligibilityCounts: Record<string, number>;
  releases: { version: string; released: string }[];
  series: {
    day: string;
    freshEvidence: boolean;
    counts: Record<string, number>;
  }[];
};
type Transition = {
  version: string | null;
  build: string | null;
  previousObserved: string | null;
  observed: string;
};

function useReport<T>(url: string) {
  const [state, set] = useState<{ url: string; data?: T; error?: string }>();
  useEffect(() => {
    let active = true;
    apiRequest<T>(url)
      .then((data) => {
        if (active) set({ url, data });
      })
      .catch((e) => {
        if (active) set({ url, error: String(e) });
      });
    return () => {
      active = false;
    };
  }, [url]);
  return state?.url === url ? state : undefined;
}

export function OsTransitions({ deviceId }: { deviceId: number }) {
  const { locale } = useLocale();
  const report = useReport<Transition[]>("/os-posture/device/" + deviceId);
  return (
    <section className="rounded-lg border bg-card p-4">
      <h3 className="font-semibold">
        {locale === "de"
          ? "Beobachtete macOS-Wechsel"
          : "Observed macOS transitions"}
      </h3>
      {report?.error ||
        (report?.data ? (
          report.data.length ? (
            <ul>
              {report.data.map((r, i) => (
                <li key={i}>
                  {r.version || "?"} ({r.build || "?"}) ·{" "}
                  {r.previousObserved
                    ? new Date(r.previousObserved).toLocaleString(locale) +
                      " → "
                    : locale === "de"
                      ? "Erste Beobachtung · "
                      : "First observation · "}
                  {new Date(r.observed).toLocaleString(locale)}
                </li>
              ))}
            </ul>
          ) : (
            "—"
          )
        ) : (
          "…"
        ))}
    </section>
  );
}

export function OsPosturePage() {
  const { locale, t } = useLocale(),
    de = locale === "de";
  const [day, setDay] = useState(new Date().toISOString().slice(0, 10)),
    [target, setTarget] = useState(""),
    [version, setVersion] = useState("");
  const [eligible, setEligible] = useState(""),
    [page, setPage] = useState(0),
    [revision, setRevision] = useState(0),
    [refreshError, setRefreshError] = useState("");
  const canRefresh = useAuthStore((s) =>
    s.user?.permissions.includes("patch:catalog-sync"),
  );
  const params = new URLSearchParams({
    day,
    page: String(page),
    revision: String(revision),
  });
  if (target) params.set("target", target);
  if (version) params.set("version", version);
  if (eligible) params.set("eligibility", eligible);
  const report = useReport<Report>("/os-posture?" + params),
    data = report?.data;
  const states: Record<string, string> = {
    compatible: de ? "Kompatibel" : "Compatible",
    incompatible: de ? "Inkompatibel" : "Incompatible",
    unknown: de ? "Unbekannt" : "Unknown",
    current: de ? "Aktuell" : "Current",
    available: de ? "Update verfügbar" : "Patch available",
  };
  const versions = Array.from(
    new Set(data?.series.flatMap((r) => Object.keys(r.counts))),
  ).sort();
  return (
    <main className="space-y-4">
      <h1 className="text-2xl font-semibold">{t.nav.osPosture}</h1>
      <p>
        {de
          ? "Macs mit aufbewahrten Inventarbeobachtungen bis zum gewählten UTC-Tag, einschließlich ausgeschiedener Geräte."
          : "Macs with retained inventory through the selected UTC day, including departed devices."}
      </p>
      <label>
        {de ? "Stichtag" : "As of"}{" "}
        <input
          type="date"
          value={day}
          max={new Date().toISOString().slice(0, 10)}
          onChange={(e) => {
            if (e.target.value) {
              setDay(e.target.value);
              setPage(0);
            }
          }}
        />
      </label>
      {report?.error && <p role="alert">{report.error}</p>}
      {data ? (
        <>
          <div className="rounded-lg border p-4 space-y-2">
            <h2>
              {de ? "Versionsverlauf · 30 Tage" : "Version adoption · 30 days"}
            </h2>
            <div className="overflow-x-auto">
              <div className="flex h-28 min-w-96 items-end gap-1">
                {data.series.map((r) => (
                  <div
                    key={r.day}
                    className="flex flex-1 flex-col-reverse"
                    title={r.day}
                    style={{
                      height: "100%",
                      justifyContent: "flex-start",
                      borderTop: r.freshEvidence
                        ? undefined
                        : "2px dashed currentColor",
                      borderBottom: data.releases.some(
                        (release) => release.released === r.day,
                      )
                        ? "3px solid currentColor"
                        : undefined,
                    }}
                  >
                    {Object.entries(r.counts)
                      .sort()
                      .map(([v, n]) => (
                        <button
                          key={v}
                          title={r.day + " · " + v + " · " + n}
                          aria-label={r.day + " · " + v + " · " + n}
                          onClick={() => {
                            setDay(r.day);
                            setVersion(v);
                            setEligible("");
                            setPage(0);
                          }}
                          style={{
                            height:
                              (100 * n) /
                                Math.max(
                                  1,
                                  ...data.series.map((a) =>
                                    Object.values(a.counts).reduce(
                                      (x, y) => x + y,
                                      0,
                                    ),
                                  ),
                                ) +
                              "%",
                            backgroundColor:
                              "hsl(" +
                              ((versions.indexOf(v) * 137) % 360) +
                              " 48% 46%)",
                          }}
                        />
                      ))}
                  </div>
                ))}
              </div>
            </div>
            <p>
              {data.series[0].day} — {day} ·{" "}
              {de
                ? "Gestrichelt: kein erhaltener Beobachtungszeitpunkt. Unterstrichen: Veröffentlichung."
                : "Dashed top: no retained observation timestamp that day. Underlined date: macOS release."}
            </p>
            <p>
              {versions.map((v) => (
                <span
                  className="mr-3"
                  key={v}
                  style={{
                    borderBottom:
                      "3px solid hsl(" +
                      ((versions.indexOf(v) * 137) % 360) +
                      " 48% 46%)",
                  }}
                >
                  {states[v] || v}
                </span>
              ))}
            </p>
          </div>
          <p>
            SOFA · {data.asOf || states.unknown}{" "}
            {canRefresh && (
              <button
                className="underline"
                onClick={() => {
                  setRefreshError("");
                  apiRequest("/os-posture/refresh", { method: "POST" })
                    .then(() => setRevision((r) => r + 1))
                    .catch((e) => setRefreshError(String(e)));
                }}
              >
                {de ? "Aktualisieren" : "Refresh"}
              </button>
            )}{" "}
            {refreshError}
          </p>
          <p>
            {data.releases
              .filter(
                (r) => r.released >= data.series[0].day && r.released <= day,
              )
              .map((r) => (
                <span className="mr-3" key={r.version + r.released}>
                  macOS {r.version} · {r.released}
                </span>
              ))}
          </p>
          <div className="flex flex-wrap gap-4">
            <label>
              {de ? "Zielversion" : "Target macOS"}{" "}
              <select
                value={data.target}
                onChange={(e) => {
                  setTarget(e.target.value);
                  setPage(0);
                }}
              >
                {data.targets.map((v) => (
                  <option key={v}>{v}</option>
                ))}
              </select>
            </label>
            <label>
              Version{" "}
              <select
                value={version}
                onChange={(e) => {
                  setVersion(e.target.value);
                  setPage(0);
                }}
              >
                <option value="">{de ? "Alle" : "All"}</option>
                {versions.map((v) => (
                  <option key={v}>{v}</option>
                ))}
              </select>
            </label>
            <label>
              {de ? "Hardware" : "Hardware eligibility"}{" "}
              <select
                value={eligible}
                onChange={(e) => {
                  setEligible(e.target.value);
                  setPage(0);
                }}
              >
                <option value="">{de ? "Alle" : "All"}</option>
                {Object.entries(data.eligibilityCounts).map(([s, n]) => (
                  <option key={s} value={s}>
                    {states[s]} ({n})
                  </option>
                ))}
              </select>
            </label>
          </div>
          <p>{data.total} Macs</p>
          <table className="w-full text-left text-sm">
            <thead>
              <tr>
                {[
                  "Mac",
                  "macOS",
                  "Build",
                  de ? "Modell" : "Model",
                  de ? "Beobachtet" : "Last observation",
                  de ? "Aktuelle Zweigversion" : "Latest on branch",
                  "Hardware",
                ].map((x) => (
                  <th key={x}>{x}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {data.devices.map((d) => (
                <tr key={d.id}>
                  <td>
                    <Link className="underline" to={"/devices/" + d.id}>
                      {d.name}
                    </Link>
                  </td>
                  <td>{d.version || "—"}</td>
                  <td>{d.build || "—"}</td>
                  <td>{d.model || "—"}</td>
                  <td>{new Date(d.observed).toLocaleDateString(locale)}</td>
                  <td>
                    {d.latest} · {states[d.patch]}
                  </td>
                  <td>{states[d.eligibility]}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <button disabled={page === 0} onClick={() => setPage(page - 1)}>
            ←
          </button>{" "}
          {page + 1}{" "}
          <button
            disabled={(page + 1) * 100 >= data.total}
            onClick={() => setPage(page + 1)}
          >
            →
          </button>
        </>
      ) : (
        !report?.error && "…"
      )}
    </main>
  );
}
