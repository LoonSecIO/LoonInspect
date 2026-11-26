import { useState } from "react";
import type { PickerApp } from "@/features/patchPolicy/apps";
import type { PatchPolicyCopy } from "@/features/patchPolicy/copy";

/** How many rows are drawn before a search: Jamf's patch catalog is a few thousand titles, and the
 *  apps with a replay are first, so they are always among these. */
const UNSEARCHED_ROWS = 40;

/**
 * The app picker (#614). Presentational, like `ReplayView`: it is handed its rows and loads none. An
 * app with nothing to draw is listed and cannot be picked, and says so (*no reference replay yet*,
 * or *no reference yet* once LoonSec's data is walked) where a count would otherwise be read as zero.
 * `labels` names the two kinds of row; the reference replays' words when it is absent.
 */
export function AppPicker({
  apps,
  selected,
  onSelect,
  copy,
  labels
}: {
  apps: PickerApp[];
  selected: string | null;
  onSelect: (replayId: string) => void;
  copy: PatchPolicyCopy;
  labels?: { has: string; none: string };
}) {
  const has = labels?.has ?? copy.appHasReplay;
  const none = labels?.none ?? copy.appNoReplay;
  const [term, setTerm] = useState("");
  const wanted = term.trim().toLowerCase();
  const matching = wanted ? apps.filter((app) => app.name.toLowerCase().includes(wanted)) : apps;
  const listed = wanted ? matching : matching.slice(0, UNSEARCHED_ROWS);

  return (
    <div className="space-y-2">
      <label htmlFor="patch-policy-app" className="text-xs font-medium uppercase tracking-wide text-muted-foreground">{copy.appHeading}</label>
      <input
        id="patch-policy-app"
        type="search"
        className="block w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        placeholder={copy.appSearch}
        value={term}
        onChange={(event) => setTerm(event.target.value)}
      />
      <ul className="max-h-44 divide-y overflow-y-auto rounded-lg border bg-card text-sm lg:max-h-[28rem]">
        {listed.map((app) => (
          <li key={app.key}>
            {app.replayId ? (
              <button
                type="button"
                aria-pressed={app.replayId === selected}
                onClick={() => onSelect(app.replayId as string)}
                className={`flex w-full flex-wrap items-baseline justify-between gap-x-2 px-3 py-2 text-left hover:bg-muted ${app.replayId === selected ? "bg-muted font-semibold" : ""}`}
              >
                <span>{app.name}</span>
                <span className="text-xs font-normal text-muted-foreground">{has}</span>
              </button>
            ) : (
              <div aria-disabled="true" className="flex flex-wrap items-baseline justify-between gap-x-2 px-3 py-2 text-muted-foreground">
                <span>{app.name}</span>
                <span className="text-xs">{none}</span>
              </div>
            )}
          </li>
        ))}
        {listed.length === 0 && <li className="px-3 py-2 text-muted-foreground">{copy.appNoMatches}</li>}
      </ul>
      {listed.length < matching.length && <p className="text-xs text-muted-foreground">{copy.appsCapped(listed.length, matching.length)}</p>}
    </div>
  );
}
