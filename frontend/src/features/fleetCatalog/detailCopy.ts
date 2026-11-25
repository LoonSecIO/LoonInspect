// The Fleet app and title page's words (#906; #907, #908 and #909 extend them), the German typed against the English. A refusal's
// `detail` other than the flag's 409 is shown as sent (see `features/ai/activityCopy.ts`). Counts arrive formatted, with a singular flag.

export const fleetDetailEnglish = {
  back: "Back to Fleet catalog", loading: "Loading application evidence…", retry: "Retry", record: "Application record", versions: "Fleet release history",
  readFailed: "This Fleet catalog record could not be read. Retry, or reload the Fleet catalog list; if the list fails too, the instance is not answering.",
  bundleMissing: "Bundle identifier unavailable", source: "Fleet manifest", titleLink: "Fleet title", asOf: "Report calculated", count: "Macs",
  recordEvidence: "Open the inventory record for the observed identity and build evidence.", localMatches: "Matching application records", jamfTitle: "Matched Jamf Patch titles",
  footprint: (installed: string, oneInstalled: boolean, selected: string, oneSelected: boolean) =>
    `${installed} of ${selected} in-scope ${oneSelected ? "Mac" : "Macs"} ${oneInstalled ? "reports" : "report"} this app.`,
  scopeMacs: (selected: string, eligible: string, oneEligible: boolean) => `${selected} of ${eligible} eligible ${oneEligible ? "Mac" : "Macs"} selected`,
  exact: "One Fleet title matches this app’s bundle identifier.", catalogFirst: "This macOS title comes from Fleet’s public catalog.",
  ambiguous: "Several channels or identities can fit the inventory evidence. Confirm the intended channel before planning an update.",
  noMatch: "The Fleet catalog has no matching macOS title for this inventory identity.",
  // #895's `unknown` has two causes, told apart by the bundle ID the header shows: none to match, or a catalog not read whole.
  catalogUnknown: (bundleMissing: boolean): string => bundleMissing
    ? "Fleet coverage is unknown: the inventory reports no bundle identifier for this app, and Fleet titles are matched by bundle identifier."
    : "Fleet coverage is unknown: Fleet’s catalog has not been read whole, so a title for this app may be missing.",
  matches: "Macs with matching inventory", fleetLatest: "Fleet catalog version", candidates: "Fleet channels", installed: "Installed builds",
  selectChannel: "Open a channel to see its Fleet release history.", noBuilds: "No matching installations were observed in the selected scope.",
  filterVersion: "Filter by exact installed version", allVersions: "All installed versions", version: "Installed version", unknown: "Version unknown",
  countNote: "A Mac with multiple installed builds can appear in more than one row.", sources: "Detection and policy evidence",
  jamfScope: "Jamf title matches describe public patch definitions. The organization’s deployment settings require separate review.",
  // Of the titles synced here only: a record can name a Jamf title this instance holds no row for (#899).
  jamfMissing: "No Jamf Patch title this instance has synced matched this inventory record.",
  jamfUnavailable: "No Jamf Patch title could match: the Jamf Patch catalog has not been synced. Open Devices › Applications › Jamf Patch and press Sync now.",
  jamfPending: "Jamf Patch matching has not finished for every record here. The next device sweep finishes it, or Sync now under Devices › Applications › Jamf Patch."
};

export type FleetDetailCopy = typeof fleetDetailEnglish;

export const fleetDetailGerman: FleetDetailCopy = {
  back: "Zurück zum Fleet-Katalog", loading: "Anwendungsnachweise werden geladen…", retry: "Erneut versuchen", record: "Anwendungseintrag", versions: "Fleet-Versionsverlauf",
  readFailed: "Dieser Eintrag des Fleet-Katalogs konnte nicht gelesen werden. Versuchen Sie es erneut oder laden Sie die Liste des Fleet-Katalogs neu; scheitert auch sie, antwortet die Instanz nicht.",
  bundleMissing: "Bundle-Kennung nicht verfügbar", source: "Fleet-Manifest", titleLink: "Fleet-Titel", asOf: "Bericht berechnet", count: "Macs",
  recordEvidence: "Der Inventareintrag zeigt die beobachtete Identität und die Nachweise zu den Builds.", localMatches: "Passende Anwendungseinträge", jamfTitle: "Passende Jamf-Patch-Titel",
  footprint: (installed, oneInstalled, selected, oneSelected) =>
    `${installed} von ${selected} ${oneSelected ? "Mac" : "Macs"} im Gerätefilter ${oneInstalled ? "meldet" : "melden"} diese App.`,
  scopeMacs: (selected, eligible, oneEligible) => `${selected} von ${eligible} ${oneEligible ? "aktuellen Jamf-Mac" : "aktuellen Jamf-Macs"} ausgewählt`,
  exact: "Ein Fleet-Titel entspricht der Bundle-Kennung dieser App.", catalogFirst: "Dieser macOS-Titel stammt aus Fleets öffentlichem Katalog.",
  ambiguous: "Mehrere Kanäle oder Identitäten passen zu den Inventardaten. Bestätigen Sie den gewünschten Kanal, bevor Sie ein Update planen.",
  noMatch: "Der Fleet-Katalog hat keinen passenden macOS-Titel für diese Inventaridentität.",
  catalogUnknown: bundleMissing => bundleMissing
    ? "Die Fleet-Abdeckung ist unbekannt: Das Inventar meldet für diese App keine Bundle-Kennung, und Fleet-Titel werden über die Bundle-Kennung zugeordnet."
    : "Die Fleet-Abdeckung ist unbekannt: Fleets Katalog wurde nicht vollständig gelesen, daher kann ein Titel für diese App fehlen.",
  matches: "Macs mit passendem Inventar", fleetLatest: "Katalogversion von Fleet", candidates: "Fleet-Kanäle", installed: "Installierte Builds",
  selectChannel: "Öffnen Sie einen Kanal, um seinen Fleet-Versionsverlauf zu sehen.", noBuilds: "Auf den Macs im Gerätefilter wurden keine passenden Installationen beobachtet.",
  filterVersion: "Nach exakter installierter Version filtern", allVersions: "Alle installierten Versionen", version: "Installierte Version", unknown: "Version unbekannt",
  countNote: "Ein Mac mit mehreren installierten Builds kann in mehreren Zeilen erscheinen.", sources: "Erkennungs- und Richtliniennachweise",
  jamfScope: "Jamf-Treffer beschreiben öffentliche Patchdefinitionen. Die Bereitstellungseinstellungen der Organisation sind gesondert zu prüfen.",
  jamfMissing: "Kein Jamf-Patch-Titel, den diese Instanz synchronisiert hat, passt zu diesem Inventareintrag.",
  jamfUnavailable: "Kein Jamf-Patch-Titel konnte passen: Der Jamf-Patch-Katalog ist noch nicht synchronisiert. Öffnen Sie Geräte › Anwendungen › Jamf Patch und klicken Sie auf Jetzt synchronisieren.",
  jamfPending: "Der Jamf-Patch-Abgleich ist hier noch nicht für jeden Eintrag abgeschlossen. Der nächste Geräte-Sweep schließt ihn ab, ebenso Jetzt synchronisieren unter Geräte › Anwendungen › Jamf Patch."
};
