import { useState } from "react";
import { ExternalLink } from "@/components/ui/external-link";
import type { FleetDetailCopy } from "@/features/fleetCatalog/detailCopy";
import type { FleetCandidate } from "@/features/fleetCatalog/migrationTypes";
import { useLocale } from "@/i18n/LocaleContext";

type Intent = keyof FleetDetailCopy["intents"];

// Each intent's guide, Fleet's or the tool's own, and the three addresses beside them; every one answered 200 on 2026-11-25.
const GUIDES: Record<Intent, string> = {
  patch: "https://fleetdm.com/guides/how-to-use-policies-for-patch-management-in-fleet",
  self: "https://fleetdm.com/guides/software-self-service",
  missing: "https://fleetdm.com/guides/automatic-software-install-in-fleet",
  custom: "https://fleetdm.com/guides/deploy-software-packages",
  contribute: "https://github.com/fleetdm/fleet/blob/main/ee/maintained-apps/README.md",
  installomator: "https://github.com/Installomator/Installomator",
  munki: "https://www.munki.org/munki/",
  appStore: "https://fleetdm.com/guides/install-app-store-apps"
};
const REQUEST = "https://fleetdm.com/articles/inside-fleet-maintained-apps#where-the-catalog-comes-from";
const API = "https://fleetdm.com/docs/api/rest-api#list-fleet-maintained-apps";
const GITOPS = "https://fleetdm.com/docs/configuration/yaml-files#patch-policy";
const WITH_TITLE: Intent[] = ["patch", "self", "missing"], NO_TITLE: Intent[] = ["custom", "contribute", "installomator", "munki", "appStore"];
const APPS = "/api/v1/fleet/software/fleet_maintained_apps", box = "rounded-md border p-3", code = "block break-all text-xs";

/** **Plan a Fleet pilot** (#909): with the one Fleet title the page speaks for, Fleet's three workflows, the API reads that confirm
 *  a pilot and, for patching, a GitOps draft; with none in a catalog read whole (`none`), the five other paths. It deploys nothing.
 *  The page keys it by slug, so an intent chosen from one list never stands in the other. */
export function FleetPilotGuide({ candidate }: { candidate?: FleetCandidate }) {
  const { t } = useLocale();
  const words = t.fleetDetail, intents = candidate ? WITH_TITLE : NO_TITLE, slug = candidate ? `${candidate.slug}/darwin` : "";
  const [intent, setIntent] = useState<Intent>(intents[0]);
  return <section className="space-y-3 rounded-xl border bg-card p-5 text-sm"><h3 className="text-lg font-semibold">{words.guidance}</h3>
    <label className="block space-y-1"><span className="font-medium">{words.workflow}</span>
      <select className="block w-full max-w-md rounded-md border bg-background p-2" value={intent}
        onChange={event => setIntent(intents.find(id => id === event.target.value) ?? intents[0])}>
        {intents.map(id => <option key={id} value={id}>{words.intents[id].title}</option>)}</select></label>
    <p>{words.intents[intent].text}</p>
    <div className="flex flex-wrap gap-x-4 gap-y-1"><ExternalLink href={GUIDES[intent]}>{words.intents[intent].guide}</ExternalLink>
      {intent === "contribute" && <ExternalLink href={REQUEST}>{words.requestGuide}</ExternalLink>}</div>
    {candidate && <details className={box}><summary className="cursor-pointer font-medium">{words.apiCheck}</summary>
      <ol className="my-2 list-decimal space-y-2 pl-5">
        <li>{words.apiFind}<code className={code}>{`GET ${APPS}?fleet_id={fleet_id}&platform=darwin&query=${encodeURIComponent(candidate.name)}`}</code>
          <code className={code}>{slug}</code></li>
        <li>{words.apiRead}<code className={code}>{`GET ${APPS}/{id}?fleet_id={fleet_id}`}</code></li>
        <li>{words.apiResult}<code className={code}>{"GET /api/v1/fleet/software/install/{install_uuid}/results"}</code></li></ol>
      <ExternalLink href={API}>{words.apiReference}</ExternalLink></details>}
    {candidate && intent === "patch" && <details className={`${box} bg-muted/20`}><summary className="cursor-pointer font-medium">{words.gitOps}</summary>
      <p className="my-2 text-muted-foreground">{words.gitOpsText}</p>
      <pre className="overflow-x-auto rounded-md border bg-background p-3 text-xs"><code>{`software:
  fleet_maintained_apps:
    - slug: ${slug}
policies:
  - name: "Check ${candidate.slug} version"
    type: patch
    fleet_maintained_app_slug: ${slug}`}</code></pre>
      <ExternalLink className="mt-2" href={GITOPS}>{words.gitOpsReference}</ExternalLink></details>}
    <p className="text-xs text-muted-foreground">{words.pilotFoot}</p>
  </section>;
}
