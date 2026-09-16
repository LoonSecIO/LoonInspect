import { HelpCircle, Power } from "lucide-react";
import { Link, Outlet } from "react-router";
import { useHasPermission } from "@/features/auth/store";
import { PERMISSIONS } from "@/features/auth/types";
import { useFlagGate } from "@/features/settings/flagStore";
import type { Translations } from "@/i18n/en";
import { useLocale } from "@/i18n/LocaleContext";

/** The flags that gate a route, which is the set that has words (`t.flagGate.areas`). */
export type GatedFlag = keyof Translations["flagGate"]["areas"];

/** Guards a route whose whole area one feature flag switches on (#402).
 *
 *  A sibling of `RequirePermission`, explaining rather than redirecting for the same
 *  reason: someone who followed a bookmark into an area an administrator has since
 *  switched off should read why it is gone. It sits inside the permission guard, so the
 *  narrower refusal wins for an account that may not open the page at all.
 *  Three states, three sentences (docs/diagnosability.md rule 1). The loading one is why
 *  this reads the store rather than fetching: a guard starting at "off" would flash a
 *  refusal on first paint, and one starting at "on" would flash the page it guards.
 */
export function RequireFlag({ flag }: { flag: GatedFlag }) {
  const { t } = useLocale();
  const gate = useFlagGate(flag);
  // The link is for the person who can act on it. Everyone else reads who to ask.
  const canToggle = useHasPermission(PERMISSIONS.FEATURE_FLAG_WRITE);

  if (gate === "on") return <Outlet />;

  if (gate === "loading") {
    return (
      <p role="status" className="px-6 py-16 text-center text-sm text-muted-foreground">
        {t.flagGate.checking}
      </p>
    );
  }

  // A switch that is off, and a switch nobody could read, are different pictures.
  const off = gate === "off";
  const words = t.flagGate.areas[flag];
  const Icon = off ? Power : HelpCircle;

  return (
    <section className="flex flex-col items-center justify-center gap-3 rounded-lg border border-dashed bg-muted/30 px-6 py-16 text-center">
      <Icon className="h-6 w-6 text-muted-foreground" />
      <h1 className="text-lg font-semibold">{off ? words.offTitle : t.flagGate.unreadableTitle}</h1>
      <p className="max-w-md text-sm text-muted-foreground">
        {off ? words.offDescription : t.flagGate.unreadableDescription}
      </p>
      {off && canToggle && (
        <Link className="text-sm underline" to="/settings/feature-flags">
          {t.flagGate.featureFlagsLink}
        </Link>
      )}
    </section>
  );
}
