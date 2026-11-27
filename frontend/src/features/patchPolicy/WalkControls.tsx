import { WALK_SOURCES, WALK_YEARS, sourceTrack, type WalkSource, type WalkYears } from "@/features/patchPolicy/walk";
import { reasonWords, type WalkCopy } from "@/features/patchPolicy/walkCopy";
import type { PatchPolicyApp } from "@/features/support/patchPolicyFeed";

const heading = "text-xs font-medium uppercase tracking-wide text-muted-foreground";
const choice = (on: boolean) =>
  `rounded-md border px-2.5 py-1.5 text-left text-sm ${on ? "border-foreground font-semibold" : "text-muted-foreground hover:text-foreground"}`;

/**
 * What the day-walk walks (#614): the app's track, the source of its release dates (Public, Jamf or
 * Fleet; Public first and the default, R12), the window, and whether to cut it to the days every
 * source covers. Presentational: it is handed `/apps`'s answer for the app and moves nothing itself.
 *
 * A source that cannot date the selected track is drawn disabled, and its sentence is printed under
 * the toggle, in the reader's language with the instance's own words beneath it. Nothing is hidden:
 * a source this organization cannot use says why, where the reader looks for it.
 */
export function WalkControls({
  app,
  track,
  source,
  years,
  align,
  onTrack,
  onSource,
  onYears,
  onAlign,
  words
}: {
  app: PatchPolicyApp;
  track: string;
  source: WalkSource;
  years: WalkYears;
  align: boolean;
  onTrack: (track: string) => void;
  onSource: (source: WalkSource) => void;
  onYears: (years: WalkYears) => void;
  onAlign: (align: boolean) => void;
  words: WalkCopy;
}) {
  const known = app.tracks.some((each) => each.track === track);
  const label = app.tracks.find((each) => each.track === track)?.label ?? track;
  const states = WALK_SOURCES.map((each) => ({ source: each, answer: sourceTrack(app, each, track) }));
  const unavailable = states.filter(({ answer }) => !answer?.available);

  return (
    <div className="space-y-4 rounded-lg border bg-card p-4">
      {app.tracks.length > 1 && (
        <fieldset className="space-y-1.5">
          <legend className={heading}>{words.trackHeading}</legend>
          <div className="flex flex-wrap gap-1.5">
            {app.tracks.map((each) => (
              <button key={each.track} type="button" aria-pressed={each.track === track} onClick={() => onTrack(each.track)} className={choice(each.track === track)}>
                {each.label}
                {each.default && <span className="ml-1.5 text-xs font-normal text-muted-foreground">({words.defaultTrack})</span>}
              </button>
            ))}
          </div>
        </fieldset>
      )}

      {/* A track the data does not list has nothing to choose a source or window for: the page says so beside this. */}
      {known && (
        <>
          <fieldset className="space-y-1.5">
            <legend className={heading}>{words.sourceHeading}</legend>
            <div className="grid gap-1.5 sm:grid-cols-3">
              {states.map(({ source: each, answer }) => {
                const usable = answer?.available === true;
                return (
                  <button
                    key={each}
                    type="button"
                    aria-pressed={each === source}
                    disabled={!usable}
                    aria-describedby={usable ? undefined : `patch-policy-source-${each}`}
                    onClick={() => onSource(each)}
                    className={`${choice(each === source)} disabled:cursor-not-allowed disabled:opacity-60`}
                  >
                    <span className="block">{words.sources[each]}</span>
                    <span className="block text-xs font-normal text-muted-foreground">{usable ? words.sourceHints[each] : words.sourceUnavailable}</span>
                  </button>
                );
              })}
            </div>
            {unavailable.length > 0 && (
              <ul className="space-y-1.5 pt-1 text-sm">
                {unavailable.map(({ source: each, answer }) => {
                  const context = { app: app.name, track: label, source: words.sourceWords[each], sourceId: each };
                  const lead = reasonWords(words, answer?.state ?? "", context, answer?.sentence ?? "");
                  return (
                    <li key={each} id={`patch-policy-source-${each}`}>
                      <b className="font-medium">{words.sources[each]}:</b> {lead}
                      {answer?.sentence && answer.sentence !== lead && <span className="block text-xs text-muted-foreground">{words.serverSaid(answer.sentence)}</span>}
                    </li>
                  );
                })}
              </ul>
            )}
          </fieldset>

          <div className="flex flex-wrap items-end gap-x-6 gap-y-3">
            <fieldset className="space-y-1.5">
              <legend className={heading}>{words.windowHeading}</legend>
              <div className="flex gap-1.5">
                {WALK_YEARS.map((each) => (
                  <button key={each} type="button" aria-pressed={each === years} onClick={() => onYears(each)} className={choice(each === years)}>
                    {words.years(each)}
                  </button>
                ))}
              </div>
            </fieldset>
            <label className="flex max-w-md items-start gap-2 text-sm">
              <input type="checkbox" className="mt-1" checked={align} onChange={(event) => onAlign(event.target.checked)} />
              <span>
                {words.alignLabel}
                <span className="block text-xs text-muted-foreground">{words.alignHint}</span>
              </span>
            </label>
          </div>
        </>
      )}
    </div>
  );
}
