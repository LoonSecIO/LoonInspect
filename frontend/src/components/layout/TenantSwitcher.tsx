import { useState } from "react";
import { switchTenant } from "@/features/auth/api";
import { useAuthStore } from "@/features/auth/store";
import { useLocale } from "@/i18n/LocaleContext";

/**
 * Which tenant this session acts for (#36). Renders nothing unless the account holds a
 * membership in a second tenant, so a single-tenant pod — every pod today — shows no
 * control at all: the switcher exists in code and is hidden while there is only one
 * (`backend/app/core/tenancy.py`).
 *
 * A switch is a new session, not a change to this one: the server revokes the current
 * credential and issues one for the target, so the page reloads rather than patching
 * state — everything on screen belonged to the tenant just left.
 */
export function TenantSwitcher() {
  const { t } = useLocale();
  const user = useAuthStore((state) => state.user);
  const [switching, setSwitching] = useState(false);
  const [failed, setFailed] = useState(false);

  if (!user || user.tenants.length < 2) return null;
  const current = user.tenants.find((tenant) => tenant.current) ?? user.tenants[0];

  async function choose(tenantId: string) {
    if (tenantId === current.id) return;
    setSwitching(true);
    setFailed(false);
    try {
      await switchTenant(tenantId);
      window.location.assign("/");
    } catch {
      setFailed(true);
      setSwitching(false);
    }
  }

  return (
    <label className="flex items-center gap-2 text-sm">
      <span className="sr-only">{t.common.actingTenant}</span>
      <select
        className={`h-9 rounded-md border border-input bg-background px-2 text-sm ${failed ? "border-destructive" : ""}`}
        value={current.id}
        disabled={switching}
        title={failed ? t.common.switchTenantFailed : t.common.actingTenant}
        onChange={(event) => void choose(event.target.value)}
      >
        {user.tenants.map((tenant) => (
          <option key={tenant.id} value={tenant.id}>
            {tenant.name}
          </option>
        ))}
      </select>
    </label>
  );
}
