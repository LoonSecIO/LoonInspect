import { ExternalLink } from "@/components/ui/external-link";
import { useLocale } from "@/i18n/LocaleContext";

type AppNote = { en: [string, string]; de: [string, string]; source: string; publisher: string };

const zwift: AppNote = {
  en: ["Zwift Launcher", "This bundle identifies the launcher. Track the game build separately when answering which version people ride on. A launcher inventory record establishes neither game runtime nor ride time."],
  de: ["Zwift Launcher", "Diese Bundle-ID bezeichnet den Launcher. Die Spielversion ist separat zu erfassen. Aus dem Launcher-Inventar lassen sich weder die laufende Spielversion noch die Fahrzeit ablesen."],
  publisher: "Zwift", source: "https://forums.zwift.com/t/zwift-launcher-1-2-0-for-windows-macos-october-2026/671979"
};
const falcon: AppNote = {
  en: ["Falcon sensor health", "For portal reconciliation, keep the Falcon agent ID in a restricted per-device Jamf extension attribute or inventory report. For Fleet, stage labels for sensor present and system extension active. Evaluate sensor health separately and treat a missing health observation as unknown. Review the vendor configuration profiles before moving the pilot."],
  de: ["Falcon-Sensorzustand", "Die Falcon-Agenten-ID für den Portalabgleich in einem zugriffsbeschränkten Jamf-Erweiterungsattribut oder Gerätebericht erfassen. Für Fleet Labels für installierte Sensoren und aktive Systemerweiterungen vorbereiten. Sensorzustand separat bewerten. Fehlende Beobachtungen bleiben unbekannt. Vor dem Pilotbetrieb die Konfigurationsprofile prüfen."],
  publisher: "Fleet", source: "https://fleetdm.com/guides/deploying-crowdstrike-with-fleet"
};
const chrome: AppNote = {
  en: ["Chrome update settings", "Review the Google Updater configuration profile before choosing a Fleet patch policy. Record the release channel, target-version settings and rollout schedule so an existing pin is visible in the pilot."],
  de: ["Update-Einstellungen für Chrome", "Vor der Auswahl einer Fleet-Patchrichtlinie das Konfigurationsprofil für Google Updater prüfen. Release-Kanal, Zielversion und Rollout-Zeitplan erfassen, damit eine vorhandene Versionsbindung im Pilotbetrieb sichtbar ist."],
  publisher: "Google Chrome Enterprise", source: "https://support.google.com/chrome/a/answer/7591084"
};
const onePassword: AppNote = {
  en: ["1Password managed settings", "Review the desktop app’s managed preferences and preserve the approved sign-in and security settings in the pilot profile. Record the desktop app version separately from the browser extension."],
  de: ["Verwaltete 1Password-Einstellungen", "Die verwalteten Einstellungen der Desktop-App prüfen und die freigegebenen Anmelde- und Sicherheitseinstellungen in das Pilotprofil übernehmen. Die Version der Desktop-App getrennt von der Browsererweiterung erfassen."],
  publisher: "1Password", source: "https://support.1password.com/mobile-device-management/"
};
const notes: Record<string, AppNote> = {
  "com.1password.1password": onePassword,
  "com.zwift.zwiftlauncher": zwift, "com.crowdstrike.falcon.app": falcon, "com.crowdstrike.falcon.agent": falcon,
  "com.google.chrome": chrome
};

export function FleetOperatorNotes({ bundleId }: { bundleId: string | null | undefined }) {
  const { locale } = useLocale();
  const note = bundleId && notes[bundleId.toLowerCase()];
  const german = locale === "de";
  const bundle = bundleId && /^[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$/.test(bundleId) ? bundleId : null;
  return <aside className="space-y-3 rounded-lg border bg-muted/20 p-4">
    {note && <div className="space-y-1">
      <h3 className="font-semibold">{note[locale][0]}</h3>
      <p className="text-sm">{note[locale][1]}</p>
      <ExternalLink className="text-sm" href={note.source}>{note.publisher}</ExternalLink>
    </div>}
    <details className="text-sm">
      <summary className="cursor-pointer font-medium">{german ? "Gerätelabel und Inventarerfassung" : "Device label and inventory check"}</summary>
      {bundle ? <>
        <p className="my-2">{german
          ? "Dieses dynamische macOS-Label findet Geräte mit dem Bundle im App-Inventar. Bei gemeinsamen Bundle-IDs den Release-Kanal vor der Zielzuweisung separat belegen."
          : "Use this dynamic macOS label to find devices reporting the bundle. If several editions share the identifier, verify the channel separately before targeting a patch."}</p>
        <pre className="overflow-x-auto rounded-md border bg-background p-2"><code>{`SELECT 1 FROM apps WHERE bundle_identifier = '${bundle}' LIMIT 1;`}</code></pre>
        <p className="my-2">{german
          ? "Für Versionsberichte den beobachteten Pfad und die Kurzversion je Installation erfassen. Ein Jamf-Erweiterungsattribut ist sinnvoll, wenn eine zusätzliche Herstellerangabe wie der Kanal oder der Sensorzustand benötigt wird."
          : "For a version report, retain the observed path and short version per installation. Use a Jamf extension attribute when the migration needs an additional vendor-specific value, such as release channel or sensor health."}</p>
      </> : <p className="my-2">{german
        ? "Zuerst die Bundle-ID oder den Herstellerbeleg über das Inventar bestätigen. Danach lässt sich ein gerätespezifisches Label erstellen."
        : "Verify the app’s bundle identifier or vendor receipt in inventory before defining a device label."}</p>}
      <div className="flex flex-wrap gap-4">
        <ExternalLink href="https://fleetdm.com/guides/managing-labels-in-fleet">Fleet labels</ExternalLink>
        <ExternalLink href="https://fleetdm.com/tables/apps">osquery apps</ExternalLink>
        <ExternalLink href="https://learn.jamf.com/r/en-US/jamf-pro-documentation-current/Computer_Extension_Attributes">Jamf extension attributes</ExternalLink>
      </div>
    </details>
  </aside>;
}
