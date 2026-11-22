import { useState } from "react";
import { ExternalLink } from "@/components/ui/external-link";
import { useLocale } from "@/i18n/LocaleContext";
import { fleetDetailCopy } from "./fleetDetailCopy";
import type { FleetCandidate } from "./migrationTypes";

const docs = {
  patch: "https://fleetdm.com/guides/how-to-use-policies-for-patch-management-in-fleet",
  self: "https://fleetdm.com/guides/software-self-service",
  missing: "https://fleetdm.com/guides/automatic-software-install-in-fleet",
  custom: "https://fleetdm.com/guides/deploy-software-packages",
  appStore: "https://fleetdm.com/guides/install-app-store-apps",
  request: "https://fleetdm.com/articles/inside-fleet-maintained-apps#where-the-catalog-comes-from",
  installomator: "https://github.com/Installomator/Installomator",
  munki: "https://www.munki.org/munki/",
  api: "https://fleetdm.com/docs/api/rest-api#list-fleet-maintained-apps",
  upstream: "https://github.com/fleetdm/fleet/blob/main/ee/maintained-apps/README.md",
  gitOps: "https://fleetdm.com/docs/configuration/yaml-files#patch-policy"
};

export function FleetPilotGuide({ candidate }: { candidate?: FleetCandidate }) {
  const { locale } = useLocale();
  const c = fleetDetailCopy[locale];
  const choices = candidate
    ? [[c.existing, c.existingText, docs.patch, c.patchGuide], [c.offer, c.offerText, docs.self, c.selfGuide], [c.missing, c.missingText, docs.missing, c.autoGuide]]
    : [[c.custom, c.customText, docs.custom, c.pkgGuide], [c.contribute, c.contributeText, docs.upstream, c.contributionGuide],
      [c.installomator, c.installomatorText, docs.installomator, "Installomator"], [c.munki, c.munkiText, docs.munki, "Munki"],
      [c.appStore, c.appStoreText, docs.appStore, c.appStoreGuide]];
  const [choice, setChoice] = useState(0);
  const [, description, url, guide] = choices[choice] || choices[0];
  return (
    <section className="space-y-3 rounded-xl border bg-card p-5">
      <h3 className="text-lg font-semibold">{c.guidance}</h3>
      <label className="block space-y-1 text-sm">
        <span className="font-medium">{c.workflow}</span>
        <select className="block w-full max-w-md rounded-md border bg-background p-2"
          value={choice} onChange={event => setChoice(Number(event.target.value))}>
          {choices.map(([title], i) => <option key={title} value={i}>{title}</option>)}
        </select>
      </label>
      <p className="text-sm">{description}</p>
      <div className="flex flex-wrap gap-4 text-sm"><ExternalLink href={url}>{guide}</ExternalLink>
        {!candidate && url === docs.upstream && <ExternalLink href={docs.request}>{c.requestGuide}</ExternalLink>}
      </div>
      {candidate && <details className="rounded-md border p-3 text-sm">
        <summary className="cursor-pointer font-medium">{locale === "de" ? "Mit der Fleet-API prüfen" : "Verify in the Fleet API"}</summary>
        <ol className="my-2 list-decimal space-y-2 pl-5">
          <li>{locale === "de" ? "Suchen Sie in der Pilotflotte nach der App. Gleichen Sie den Slug ab und übernehmen Sie die numerische App-ID." : "List the apps in the pilot fleet. Match the slug and record its numeric maintained-app ID."}
            <code className="block break-all text-xs">GET /api/v1/fleet/software/fleet_maintained_apps?fleet_id=&#123;fleet_id&#125;&amp;platform=darwin&amp;query={encodeURIComponent(candidate.name)}</code>
            <code className="text-xs">{candidate.slug}/darwin</code></li>
          <li>{locale === "de" ? "Lesen Sie Version und Zielgruppe für diese ID. Ist software_title_id leer, wurde der Installer dieser Flotte noch nicht hinzugefügt." : "Read the version for that ID. A null software_title_id means the installer has yet to be added to this fleet."}
            <code className="block break-all text-xs">GET /api/v1/fleet/software/fleet_maintained_apps/&#123;id&#125;?fleet_id=&#123;fleet_id&#125;</code></li>
          <li>{locale === "de" ? "Prüfen Sie nach der Pilotinstallation das Ergebnis mit ihrer UUID und bestätigen Sie die Version im nächsten Geräteinventar." : "After a pilot install, read its result using the install UUID and confirm the version in the next host inventory."}
            <code className="block break-all text-xs">GET /api/v1/fleet/software/install/&#123;install_uuid&#125;/results</code></li>
        </ol>
        <ExternalLink href={docs.api}>{locale === "de" ? "Fleet-API-Referenz" : "Fleet REST API reference"}</ExternalLink>
      </details>}
      {candidate && choice === 0 && (
        <details className="rounded-md border bg-muted/20 p-3 text-sm">
          <summary className="cursor-pointer font-medium">{locale === "de" ? "GitOps-Entwurf für die Pilotflotte" : "GitOps draft for the pilot fleet"}</summary>
          <p className="my-2 text-muted-foreground">{locale === "de" ? "Ergänzen Sie die vorhandene Konfiguration der Pilotflotte. Diese Richtlinie prüft bereits installierte Versionen. Aktivieren Sie die Installation nach der Auswertung am Pilotgerät."
            : "Merge these entries into the pilot fleet’s configuration. The policy checks existing installations. Review the pilot result before enabling install automation."}</p>
          <pre className="overflow-x-auto rounded-md border bg-background p-3 text-xs"><code>{`software:
  fleet_maintained_apps:
    - slug: ${candidate.slug}/darwin
policies:
  - name: "Check ${candidate.slug} version"
    type: patch
    fleet_maintained_app_slug: ${candidate.slug}/darwin`}</code></pre>
          <ExternalLink className="mt-2" href={docs.gitOps}>{locale === "de" ? "Fleet-GitOps-Referenz" : "Fleet GitOps reference"}</ExternalLink>
        </details>
      )}
      <p className="text-xs text-muted-foreground">{c.pilotFoot}</p>
    </section>
  );
}
