import type { DefinitionRefusal } from "@/features/patchPolicy/definitions";
import type { OfferedDefinition } from "@/features/patchPolicy/walk";
import { reasonWords, type ReasonContext, type WalkCopy } from "@/features/patchPolicy/walkCopy";

const heading = "text-xs font-medium uppercase tracking-wide text-muted-foreground";
const choice = (on: boolean) =>
  `rounded-md border px-2.5 py-1.5 text-left text-sm hyphens-manual disabled:cursor-not-allowed disabled:opacity-60 ${on ? "border-foreground font-semibold" : "text-muted-foreground hover:text-foreground"}`;

/**
 * The built-in policy definitions (#954), listed beside the slider's stops on the day-walk only: one
 * button each, pressed while it is loaded, as a stop's button is. Presentational: it is handed what
 * the walk offers and moves nothing itself; selecting one is selecting a policy, as a stop is, and the
 * address carries it (`?policy=<id>`).
 *
 * A definition the walk did not run on this data is drawn disabled, and its sentence is printed under
 * the buttons, in the reader's language with the instance's own words beneath it, as the source
 * toggle does for a source that cannot date the track. Keyboard and screen reader meet it as they
 * meet the stops' buttons: each is a button in the tab order with its pressed state, and the group
 * is named by its legend.
 */
export function DefinitionPicker({
  offered,
  selected,
  onSelect,
  words,
  context
}: {
  offered: OfferedDefinition[];
  selected: string | null;
  onSelect: (id: string) => void;
  words: WalkCopy;
  context: ReasonContext;
}) {
  if (offered.length === 0) return null;
  const nameOf = (each: OfferedDefinition) => words.definitionNames[each.definition.id] ?? each.definition.name;
  const refused = offered.flatMap((each): [OfferedDefinition, DefinitionRefusal][] => (each.refusal ? [[each, each.refusal]] : []));
  return (
    <div className="mt-3 border-t pt-3">
      <fieldset className="space-y-1.5">
        <legend className={heading}>{words.definitionsLegend}</legend>
        <div className="grid gap-1.5 sm:grid-cols-3">
          {offered.map((each) => {
            const usable = !each.refusal;
            return (
              <button
                key={each.definition.id}
                type="button"
                aria-pressed={each.definition.id === selected}
                disabled={!usable}
                aria-describedby={usable ? undefined : `patch-policy-definition-${each.definition.id}`}
                onClick={() => onSelect(each.definition.id)}
                className={choice(each.definition.id === selected)}
              >
                <span className="block">{nameOf(each)}</span>
                {!usable && <span className="block text-xs font-normal text-muted-foreground">{words.definitionUnavailable}</span>}
              </button>
            );
          })}
        </div>
        <p className="text-xs text-muted-foreground">{words.definitionsHint}</p>
        {refused.length > 0 && (
          <ul className="space-y-1.5 pt-1 text-sm">
            {refused.map(([each, refusal]) => {
              const lead = reasonWords(words, refusal.reason, context, refusal.sentence);
              return (
                <li key={each.definition.id} id={`patch-policy-definition-${each.definition.id}`}>
                  <b className="font-medium">{nameOf(each)}:</b> {lead}
                  {refusal.sentence !== lead && <span className="block text-xs text-muted-foreground">{words.serverSaid(refusal.sentence)}</span>}
                </li>
              );
            })}
          </ul>
        )}
      </fieldset>
    </div>
  );
}
