import { IntelligenceAccess } from "@/features/system/IntelligenceAccess";
import { PERMISSIONS } from "@/features/auth/types";
import { useHasPermission } from "@/features/auth/store";
import { useLocale } from "@/i18n/LocaleContext";

/**
 * Settings › Intelligence Access (#622): how this instance keeps vulnerability
 * intelligence current, apart from Data Sharing, because paying and contributing are
 * separate decisions and neither may change the other. Paid access is its first panel;
 * the contribution route's state joins it with the receipt work.
 */
export function IntelligenceAccessPage() {
  const { t } = useLocale();
  const canWrite = useHasPermission(PERMISSIONS.SYSTEM_WRITE);
  return (
    <div className="max-w-3xl space-y-8">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">{t.nav.intelligenceAccess}</h1>
        <p className="mt-1 text-sm text-muted-foreground">{t.intelligence.pageDescription}</p>
      </div>
      <IntelligenceAccess canWrite={canWrite} />
    </div>
  );
}
