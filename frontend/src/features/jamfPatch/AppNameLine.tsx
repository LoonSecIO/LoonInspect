import { appNameMarker } from "@/features/jamfPatch/appNameMarker";
import type { JamfPatchTitle } from "@/features/jamfPatch/types";
import type { Translations } from "@/i18n/en";

/** The title's app name, and where it came from when that is worth saying (#478).
 *
 *  One component for both surfaces — the row on the Jamf Patch table and the title block
 *  an operator lands on from it — so the row and the page cannot come to disagree about a
 *  name. `appNameMarker` decides; this only paints. A `jamf` name is shown plain: the
 *  ordinary case is not an annotation.
 */
export function AppNameLine({
  title,
  t,
  className
}: {
  title: Pick<JamfPatchTitle, "appName" | "appNameSource">;
  t: Translations;
  className?: string;
}) {
  const marker = appNameMarker(title);
  if (marker === "none") return null;

  const tp = t.jamfPatch;
  if (marker === "unnamed") {
    return (
      <span className={className} title={tp.appNameUnnamedHint}>
        {tp.appNameUnnamed}
      </span>
    );
  }

  return (
    <span className={className}>
      {title.appName}
      {marker === "derived" && <span title={tp.appNameDerivedHint}> · {tp.appNameDerived}</span>}
    </span>
  );
}
