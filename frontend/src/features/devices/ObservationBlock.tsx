import { useEffect, useRef, useState } from "react";
import { getDeviceObservation } from "@/features/devices/api";
import type { DeviceObservation, ObservedEntry, SectionObservation } from "@/features/devices/types";
import { useLocale } from "@/i18n/LocaleContext";

/** Entries shown before the rest collapse behind a count. */
const ENTRIES_SHOWN = 25;

type Loaded = { state: "ready"; value: DeviceObservation } | { state: "failed" };

function scalar(value: unknown): string {
  if (value === null || value === undefined) return "—";
  if (Array.isArray(value)) return value.length ? value.map(String).join(", ") : "—";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

function entryLabel(entry: ObservedEntry): string {
  if (entry.label) return entry.label;
  for (const key of ["name", "username", "groupId", "profileIdentifier", "definitionId", "commonName", "version"]) {
    const value = entry.body[key];
    if (value !== undefined && value !== null && String(value) !== "") return String(value);
  }
  return Object.values(entry.body).map(String).join(" ");
}

/**
 * What the ledger holds for this Mac, by section (#368). Lazy like the tiles: nothing is
 * requested until it scrolls into view, so the device page's first paint stays two cheap
 * reads. Every section renders one of four states in words — present, empty, not
 * observed, outside the aperture — and the four never look alike; an absent section is a
 * statement, not a blank.
 */
export function ObservationBlock({ deviceId }: { deviceId: number }) {
  const { t } = useLocale();
  const to = t.devices.detail.observation;
  const tc = t.changes;
  const sentinel = useRef<HTMLElement>(null);
  const [loaded, setLoaded] = useState<{ id: number; result: Loaded } | null>(null);
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});

  useEffect(() => {
    const element = sentinel.current;
    if (!element) return;
    let requested = false;
    let cancelled = false;
    const load = () => {
      if (requested) return;
      requested = true;
      getDeviceObservation(deviceId)
        .then((value) => {
          if (!cancelled) setLoaded({ id: deviceId, result: { state: "ready", value } });
        })
        .catch(() => {
          if (!cancelled) setLoaded({ id: deviceId, result: { state: "failed" } });
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
  }, [deviceId]);

  const current = loaded && loaded.id === deviceId ? loaded.result : null;
  const observation = current?.state === "ready" ? current.value : null;

  const stateSentence = (section: SectionObservation): string => {
    switch (section.state) {
      case "present":
        return section.entries.length ? to.entries(section.entryCount) : to.present;
      case "empty":
        return to.empty;
      case "not_observed":
        return to.notObserved;
      case "outside_aperture":
        return to.outsideAperture;
    }
  };

  return (
    <section ref={sentinel} className="space-y-3">
      <div>
        <h2 className="text-lg font-semibold">{to.heading}</h2>
        <p className="text-sm text-muted-foreground">
          {observation === null
            ? current?.state === "failed"
              ? to.errorLoading
              : to.loading
            : observation.observed
              ? to.observedAt(observation.observedAt ? new Date(observation.observedAt).toLocaleString() : "—")
              : to.neverObserved}
        </p>
      </div>
      {current?.state === "failed" && <p className="text-sm text-destructive">{to.errorLoading}</p>}
      {observation && (
        <>
          <section className="rounded-lg border bg-card p-4 text-sm">
            <h3 className="font-medium">{to.groupsHeading}</h3>
            {observation.groups.length === 0 ? (
              <p className="mt-1 text-muted-foreground">{to.groupsNone}</p>
            ) : (
              <ul className="mt-1 flex flex-wrap gap-2">
                {observation.groups.map((group) => (
                  <li key={group.groupId} className="rounded-full border px-3 py-1 text-xs">
                    {group.name ?? group.groupId}
                    <span className="ml-1 text-muted-foreground">{group.smart === null ? "" : group.smart ? to.smart : to.static}</span>
                    {group.departedAt && (
                      <span className="ml-1 text-destructive">{to.gone(new Date(group.departedAt).toLocaleDateString())}</span>
                    )}
                  </li>
                ))}
              </ul>
            )}
          </section>
          <div className="grid gap-3 md:grid-cols-2">
            {observation.sections.map((section) => {
              const open = expanded[section.name] ?? false;
              const shown = open ? section.entries : section.entries.slice(0, ENTRIES_SHOWN);
              return (
                <section key={section.name} className="rounded-lg border bg-card p-4 text-sm">
                  <div className="flex flex-wrap items-baseline justify-between gap-2">
                    <h3 className="font-medium">{tc.sections[section.name] ?? section.name}</h3>
                    <span className={`text-xs ${section.state === "present" ? "text-muted-foreground" : "text-muted-foreground italic"}`}>
                      {stateSentence(section)}
                    </span>
                  </div>
                  {section.state === "present" && section.body && (
                    <dl className="mt-2 grid grid-cols-[minmax(0,1fr)_minmax(0,2fr)] gap-x-3 gap-y-1">
                      {Object.entries(section.body).map(([key, value]) => (
                        <div key={key} className="contents">
                          <dt className="truncate text-xs text-muted-foreground">{key}</dt>
                          <dd className="break-words font-mono text-xs">{scalar(value)}</dd>
                        </div>
                      ))}
                    </dl>
                  )}
                  {section.state === "present" && section.entries.length > 0 && (
                    <>
                      <ul className="mt-2 space-y-0.5">
                        {shown.map((entry, index) => (
                          <li key={`${entry.kind}-${index}`} className="truncate text-xs" title={JSON.stringify(entry.body)}>
                            {entryLabel(entry)}
                          </li>
                        ))}
                      </ul>
                      {section.entries.length > ENTRIES_SHOWN && (
                        <button
                          type="button"
                          className="mt-1 text-xs underline decoration-dotted underline-offset-4"
                          onClick={() => setExpanded((held) => ({ ...held, [section.name]: !open }))}
                        >
                          {open ? to.showFewer : to.showAll(section.entries.length)}
                        </button>
                      )}
                    </>
                  )}
                </section>
              );
            })}
          </div>
        </>
      )}
    </section>
  );
}
