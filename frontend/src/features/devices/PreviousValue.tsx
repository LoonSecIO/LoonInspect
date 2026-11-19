import { useEffect, useId, useRef, useState } from "react";
import { loadPreviousValue, type HistoryValue, type PreviousRead } from "./history";
import type { historyEnglish } from "./historyCopy";

/** Recorded states that hold no value: missing evidence, never a zero and never the same value (#617). */
const MISSING = ["not_recorded", "not_observed", "outside_aperture"];

/** A displayed history value whose detail names the newest earlier state recording a different value. Hover,
 *  keyboard focus and a tap open it; its action selects that state through the card's own selection (#617). */
export function PreviousValue(props: {
  deviceId: number; point: string; slot: string; label: string; text: string; copy: typeof historyEnglish;
  format: (value: HistoryValue) => string; date: (value: string) => string; onSelect: (point: string) => void;
}) {
  const { deviceId, point, slot, text, copy } = props;
  const [open, setOpen] = useState(false);
  const [asked, setAsked] = useState(false);
  const [read, setRead] = useState<{ value?: PreviousRead; error?: boolean } | null>(null);
  const pressed = useRef(""); // What pressed the value: a tap toggles the detail; a mouse or a key only opens it.
  const trigger = useRef<HTMLButtonElement>(null);
  const id = useId();
  useEffect(() => {
    if (!asked || read) return;
    let live = true;
    loadPreviousValue(deviceId, point, slot).then((value) => live && setRead({ value }), () => live && setRead({ error: true }));
    return () => {
      live = false;
    };
  }, [asked, read, deviceId, point, slot]);
  const show = (next: boolean) => {
    setOpen(next);
    if (next) setAsked(true);
  };
  const found = read?.value?.previous;
  return (
    // One box holds the value and its detail, so the pointer can travel onto the detail's action.
    <div className="relative inline-block" onPointerEnter={(e) => e.pointerType === "mouse" && show(true)}
      onPointerLeave={(e) => e.pointerType === "mouse" && show(false)} onFocus={() => pressed.current || show(true)}
      onBlur={(e) => { if (!e.currentTarget.contains(e.relatedTarget as Node | null)) { pressed.current = ""; show(false); } }}
      onKeyDown={(e) => { if (e.key === "Escape") { pressed.current = "key"; trigger.current?.focus(); show(false); } }}>
      <button ref={trigger} type="button" aria-expanded={open} aria-controls={open ? id : undefined}
        aria-label={`${props.label}: ${text}. ${copy.previous.hint}`} className="underline decoration-dotted underline-offset-4"
        onPointerDown={(e) => { pressed.current = e.pointerType; }}
        onClick={() => { const tap = ["touch", "pen"].includes(pressed.current); pressed.current = ""; show(tap ? !open : true); }}>
        {text}
      </button>
      {open && (
        <div id={id} className="absolute right-0 top-full z-20 w-72 max-w-[80vw] pt-1 text-left text-xs font-normal">
          <div className="space-y-1 rounded border bg-card p-3 shadow-md">
            {!read ? <p role="status">{copy.previous.reading}</p>
              : read.error ? <p role="alert">{copy.previous.failed} <button type="button" className="underline" onClick={() => setRead(null)}>{copy.retry}</button></p>
              : found ? (
                <>
                  <p>{copy.previous.label}: <span className="font-semibold">{props.format(found)}</span></p>
                  {MISSING.includes(found.state) && <p className="text-muted-foreground">{copy.previous.missing}</p>}
                  <p className="text-muted-foreground">{copy.observed}: <time dateTime={found.observedAt}>{props.date(found.observedAt)}</time></p>
                  <button type="button" className="underline underline-offset-4" onClick={() => props.onSelect(found.id)}>{copy.previous.select}</button>
                </>
              ) : <p>{read.value?.complete ? copy.previous.none : copy.previous.notRead(read.value?.searched ?? 0)}</p>}
          </div>
        </div>
      )}
    </div>
  );
}
