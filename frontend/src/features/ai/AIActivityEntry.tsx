import { Link } from "react-router";
import { Activity, ArrowUpRight } from "lucide-react";
import { useHasPermission } from "@/features/auth/store";
import { PERMISSIONS } from "@/features/auth/types";
import { useLocale } from "@/i18n/LocaleContext";
import { activityPath } from "./activity";

export function AIActivityEntry() {
  const canRead = useHasPermission(PERMISSIONS.SYSTEM_READ);
  const de = useLocale().locale === "de";
  if (!canRead) return null;
  return <Link to={activityPath} className="flex items-center gap-3 rounded-lg border bg-card p-4 hover:bg-muted/50">
    <Activity className="size-5 shrink-0 text-primary" aria-hidden="true" />
    <div className="flex-1"><span className="font-semibold">{de ? "KI-Aktivität" : "AI Activity"}</span>
      <p className="text-sm text-muted-foreground">{de ? "Aufrufe nach Dienst und Zweck, Wartezeiten und aktueller Rückstau." : "Calls by service and purpose, waiting time, and whether processing is keeping up."}</p></div>
    <ArrowUpRight className="size-4" aria-hidden="true" />
  </Link>;
}
