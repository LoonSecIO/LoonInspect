import { Link } from "react-router";
import type { IntegrationVendor } from "@/features/integrations/types";
import { useLocale } from "@/i18n/LocaleContext";

const manageLinkClasses =
  "inline-flex h-9 w-fit items-center justify-center rounded-md border border-input bg-background px-3 text-sm font-medium transition-colors hover:bg-accent hover:text-accent-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring";

function initials(name: string): string {
  return name.slice(0, 2).toUpperCase();
}

export function IntegrationCard({ vendor }: { vendor: IntegrationVendor }) {
  const { t } = useLocale();
  const copy = t.integrations.vendors[vendor.id];

  return (
    <div className="flex flex-col justify-between gap-4 rounded-lg border bg-card p-4">
      <div className="flex items-start gap-3">
        <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-md bg-muted text-sm font-semibold text-muted-foreground">
          {vendor.logoUrl ? (
            <>
              <img src={vendor.logoUrl} alt="" className={`h-6 w-6 object-contain${vendor.logoUrlDark ? " dark:hidden" : ""}`} />
              {vendor.logoUrlDark && <img src={vendor.logoUrlDark} alt="" className="h-6 w-6 object-contain hidden dark:block" />}
            </>
          ) : (
            initials(copy.name)
          )}
        </div>
        <div>
          <p className="font-medium leading-tight">{copy.name}</p>
          {copy.subtitle && <p className="text-xs text-muted-foreground">{copy.subtitle}</p>}
        </div>
      </div>

      <p className="text-sm text-muted-foreground">{copy.description}</p>

      {vendor.status === "available" && vendor.href ? (
        <Link to={vendor.href} className={`${manageLinkClasses} self-start`}>
          {t.common.manage}
        </Link>
      ) : (
        <span className="w-fit rounded-full bg-muted px-2 py-1 text-xs font-medium text-muted-foreground">
          {t.common.comingSoon}
        </span>
      )}
    </div>
  );
}
