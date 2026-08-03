import { useEffect, useState } from "react";
import { NavLink, Outlet } from "react-router";
import { listConnections } from "@/features/mdm/api";
import { listFeatureFlags } from "@/features/settings/api";
import { cn } from "@/lib/utils";
import { useLocale } from "@/i18n/LocaleContext";

const tabClasses = "border-b-2 px-1 pb-2 text-sm font-medium transition-colors";
const tabStateClasses = (isActive: boolean) =>
  isActive
    ? "border-primary text-foreground"
    : "border-transparent text-muted-foreground hover:text-foreground";

export function ApplicationsPage() {
  const { t } = useLocale();
  const [hasJamfProCapability, setHasJamfProCapability] = useState(false);
  const [jamfPatchFlagEnabled, setJamfPatchFlagEnabled] = useState(false);

  // A connection's Jamf Pro capability normally gates the tab, but the
  // jamf_patch feature flag (Settings > Feature Flags) can force it visible
  // regardless — e.g. to preview the feed before wiring up a real connection.
  const jamfPatchEnabled = hasJamfProCapability || jamfPatchFlagEnabled;

  useEffect(() => {
    let cancelled = false;

    listConnections()
      .then((connections) => {
        if (cancelled) return;
        setHasJamfProCapability(connections.some((c) => c.isActive && c.capabilityJamfPro));
      })
      .catch(() => {
        if (!cancelled) setHasJamfProCapability(false);
      });

    listFeatureFlags()
      .then((flags) => {
        if (cancelled) return;
        setJamfPatchFlagEnabled(flags.some((flag) => flag.key === "jamf_patch" && flag.enabled));
      })
      .catch(() => {
        if (!cancelled) setJamfPatchFlagEnabled(false);
      });

    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <section className="space-y-6">
      <div>
        <p className="text-sm font-medium text-muted-foreground">{t.applications.eyebrow}</p>
        <h1 className="text-3xl font-bold tracking-tight">{t.applications.title}</h1>
        <p className="mt-1 text-sm text-muted-foreground">{t.applications.description}</p>
      </div>

      <div className="flex gap-4 border-b">
        <NavLink to="/devices/applications" end className={({ isActive }) => cn(tabClasses, tabStateClasses(isActive))}>
          {t.applications.tabInstalled}
        </NavLink>
        {jamfPatchEnabled && (
          <NavLink
            to="/devices/applications/jamf-patch"
            className={({ isActive }) => cn(tabClasses, tabStateClasses(isActive))}
          >
            {t.jamfPatch.tabLabel}
          </NavLink>
        )}
      </div>

      <Outlet />
    </section>
  );
}
