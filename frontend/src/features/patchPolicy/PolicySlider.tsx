import type { ReactNode } from "react";
import type { PatchPolicyCopy } from "@/features/patchPolicy/copy";
import { SLIDER_STOPS, type SliderStop } from "@/features/patchPolicy/replay";

/**
 * The patch-policy slider (#614), shared by the reference replay and the day-walk: a range input
 * over the eight stops (0, 1, 3, 7, 14, 30 and 60 days, then Never; each label the days the stop
 * waits), the stops as buttons under it, and the stop's rule in a sentence. Anything a view adds
 * about its own device (waiting for promotion, say) goes in `children`, under the rule.
 *
 * The day-walk alone adds `control`, the built-in policy definitions beside the stops (#954), and
 * `loaded` when one is selected: then no stop is pressed, the range sits on the stop the definition's
 * `otherwise` is and names the definition to a screen reader, and the definition's rule is the one
 * sentence under the slider. Moving the range or pressing a stop selects that stop again.
 *
 * The buttons are eight equal columns, and the range input is inset by half a column on each side
 * (one sixteenth, less half the thumb's 16 px) so its thumb sits over the stop it names. Both are
 * written for eight stops; `PatchPolicyPage.test.tsx` holds them to `SLIDER_STOPS`.
 */
export function PolicySlider({
  stop,
  onStop,
  copy,
  loaded,
  control,
  children
}: {
  stop: SliderStop;
  onStop: (stop: SliderStop) => void;
  copy: PatchPolicyCopy;
  loaded?: { name: string; said: string };
  control?: ReactNode;
  children?: ReactNode;
}) {
  return (
    <div className="rounded-lg border bg-card p-4">
      <label htmlFor="patch-policy-stop" className="text-xs font-medium uppercase tracking-wide text-muted-foreground">{copy.policyHeading}</label>
      {/* Inset by half a column so the thumb sits over the stop it names. */}
      <div className="px-[calc(100%/16_-_8px)] pt-3">
        <input
          id="patch-policy-stop"
          type="range"
          className="block w-full"
          min={0}
          max={SLIDER_STOPS.length - 1}
          step={1}
          value={SLIDER_STOPS.indexOf(stop)}
          aria-valuetext={loaded ? loaded.name : copy.stops[stop]}
          onChange={(event) => onStop(SLIDER_STOPS[Number(event.target.value)])}
        />
      </div>
      <div className="grid grid-cols-8 pt-1">
        {SLIDER_STOPS.map((each) => {
          const pressed = !loaded && each === stop;
          return (
            <button
              key={each}
              type="button"
              aria-pressed={pressed}
              onClick={() => onStop(each)}
              className={`rounded-md px-0.5 py-1 text-xs leading-tight sm:text-sm ${pressed ? "font-semibold text-foreground" : "text-muted-foreground hover:text-foreground"}`}
            >
              {copy.stops[each]}
            </button>
          );
        })}
      </div>
      {control}
      <p className="pt-2 text-sm text-muted-foreground">{loaded ? loaded.said : copy.policySaid(stop)}</p>
      {children}
    </div>
  );
}
