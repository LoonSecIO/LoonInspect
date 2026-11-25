import type { FleetAssessment, ImpactUnavailable } from "./migrationTypes";

// The Fleet app and title page's words (#906; #907, #908 and #909 extend them), the German typed against the English. A refusal's
// `detail` other than the flag's 409 is shown as sent (see `features/ai/activityCopy.ts`). Counts arrive formatted, with a singular flag.
// The verdict and the patch-policy word are the list's (`fleetPlanning.reasons`, `.policy`, #903), so the two pages cannot disagree.

export const fleetDetailEnglish = {
  back: "Back to Fleet catalog", loading: "Loading application evidence…", retry: "Retry", record: "Application record", versions: "Fleet release history",
  readFailed: "This Fleet catalog record could not be read. Retry, or reload the Fleet catalog list; if the list fails too, the instance is not answering.",
  bundleMissing: "Bundle identifier unavailable", source: "Fleet manifest", titleLink: "Fleet title", asOf: "Report calculated", count: "Macs",
  recordEvidence: "Open the inventory record for the observed identity and build evidence.", localMatches: "Matching application records", jamfTitle: "Matched Jamf Patch titles",
  footprint: (installed: string, oneInstalled: boolean, selected: string, oneSelected: boolean) =>
    `${installed} of ${selected} in-scope ${oneSelected ? "Mac" : "Macs"} ${oneInstalled ? "reports" : "report"} this app.`,
  scopeMacs: (selected: string, eligible: string, oneEligible: boolean) => `${selected} of ${eligible} current Jamf ${oneEligible ? "Mac" : "Macs"} selected`,
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
  jamfMissing: "No Jamf Patch title this instance has synced matches these installations.",
  jamfUnavailable: "No Jamf Patch title could match: the Jamf Patch catalog has not been synced. Open Devices › Applications › Jamf Patch and press Sync now.",
  jamfPending: "Jamf Patch matching has not finished for every record here. The next device sweep finishes it, or Sync now under Devices › Applications › Jamf Patch.",
  management: { recurring: "Recurring update review", one_time: "One-time update review", observe: "Monitor for changes" } satisfies Record<FleetAssessment["management"], string>,
  cadence: (versions: string, one: boolean) => `Fleet dated ${versions} ${one ? "version" : "versions"} of this title in the past 90 days; two or more suggest recurring review.`,
  cadenceUnread: "How often Fleet updates this title is unknown until its release history is read.", planLink: "Build a patch plan for these Macs",
  // In distinct builds (#896). A copy of a build's answer can trail the catalog's, which the verdict reads, by up to an hour (#917).
  installedFindings: "Findings on installed builds", covered: "Assessed builds", uncovered: "Unassessed builds",
  affected: "With findings", highCritical: "With high or critical findings", exploited: "With known exploited findings",
  findingsLag: "Each Mac keeps its own copy of a build’s answer, which the hourly refresh brings up to date, so for up to an hour after a corpus release or a sweep these counts can differ from the verdict above.",
  observedCount: (changes: string, oneChange: boolean, macs: string, oneMac: boolean, days: string) =>
    `${changes} recorded version ${oneChange ? "change" : "changes"} on ${macs} ${oneMac ? "Mac" : "Macs"} in the last ${days} days.`,
  observedLast: (at: string) => `Last recorded ${at}.`, observedTitle: "Updates observed after Fleet publication",
  // #900's window is always 90 days, and 0 is also what a change log that records no applications holds.
  observedSource: "A 0 here can mean the change log is not recording applications (Settings › Change tracking), and a change log kept under 90 days counts only the days it keeps.",
  observedLag: (days: string, oneDay: boolean, pairs: string, onePair: boolean) =>
    `Median ${days} ${oneDay ? "day" : "days"} after Fleet dated the version, across ${pairs} Mac/version ${onePair ? "pair" : "pairs"}.`,
  observedNoLag: "No recorded upgrade on these Macs in this window could be paired with a version Fleet’s history has dated.",
  observedNotMeasured: "Upgrade timing is measured only for an app matched to one Fleet title.",
  observedNote: "From the change log: the interval ends when a sweep first recorded the upgrade on a Mac, so how often inventory is collected adds to it.",
  // Compare a target version (#908): #899's impact and #897's rows for Fleet's latest or a dated version. A row's verdict is the Jamf
  // Patch title page's sentence or rule word, picked by code, and its counts take that page's legend (`jamfPatch.rules`).
  impact: "Compare a target version", target: "Fleet target", fetchImpact: "Loading target comparison…", resetTarget: "Use latest Fleet version",
  installedScope: "Matched Macs", older: "Below target", atOrAbove: "At or above target", chooseFromHistory: "Select another target from the release history below.",
  pinCheck: "Before pinning this version, check that Fleet still offers it under Actions › Versions.", impactError: "Could not compare this target.",
  impactNoReason: "No reason came back. Retry; if it fails again, the app container’s log shows the request and its error.",
  // `identity_review` also covers an app with no bundle ID and an assumed Jamf match (§27 step 11), so the sentence names all four.
  impactUnavailable: (reason: ImpactUnavailable, target: string): string => ({
    catalog_incomplete: "Device impact is unavailable: Fleet’s catalog is not completely read. It returns after the next complete check.",
    no_fleet_title: "No Fleet title matches this app’s bundle identifier, so there is no target to compare against.",
    identity_review: "Device impact is unavailable until this app’s identity is reviewed: it has no bundle identifier, more than one Fleet channel or Jamf title fits it, or its Jamf match is assumed.",
    unordered_target: `Device impact is unavailable: Fleet’s version ${target} cannot be ordered against installed versions. Choose a dotted release from the history below.`
  } satisfies Record<ImpactUnavailable, string>)[reason],
  findings: "Vulnerability and policy evidence", allPolicy: "Policy across all installed builds", exempt: "Exempt", unassessed: "No policy judgment",
  scanner: "Findings come from the vulnerability corpus’s answer for each exact build, not from a scan of these Macs.",
  findingScope: "Comparisons cover older installed builds. Each row compares one observed build with the selected target.",
  noOlder: "No comparable older build in this scope.", risk: "Findings at target", due: (date: string) => `Due ${date}`,
  unordered: (builds: string, one: boolean, target: string) => one
    ? `${builds} installed build has a version string that cannot be ordered against ${target}. It is listed under Installed builds and left out of this table.`
    : `${builds} installed builds have version strings that cannot be ordered against ${target}. They are listed under Installed builds and left out of this table.`,
  exactDelta: (addressed: string, introduced: string, remaining: string) => `${addressed} addressed · ${introduced} introduced · ${remaining} remaining`,
  netDelta: (net: number, n: string) => net === 0 ? "Same total findings" : `${n} ${net > 0 ? "fewer" : "more"} ${Math.abs(net) === 1 ? "finding" : "findings"} in total`,
  capped: "Finding IDs are capped. Only the change in total can be compared.", proof: "Inspect finding IDs",
  addressed: "Addressed at target", introduced: "Introduced at target", remaining: "Present on both builds", ambiguousBuild: "Identity requires review",
  off: "Corpus unavailable", unknown_source: "Installed build outside corpus", unknown_target: "Target build outside corpus",
  kev: (n: string) => `Known exploited on installed build: ${n}`, defaultRule: "Organization default rule", overrideRule: "Title-specific rule",
  policyIdentity: "Not judged until this build’s identity is reviewed: more than one Fleet or Jamf title fits it, or its Jamf match is assumed.",
  policyNoTitle: "Not judged: no Jamf Patch title matches this build."
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
  jamfMissing: "Kein Jamf-Patch-Titel, den diese Instanz synchronisiert hat, passt zu diesen Installationen.",
  jamfUnavailable: "Kein Jamf-Patch-Titel konnte passen: Der Jamf-Patch-Katalog ist noch nicht synchronisiert. Öffnen Sie Geräte › Anwendungen › Jamf Patch und klicken Sie auf Jetzt synchronisieren.",
  jamfPending: "Der Jamf-Patch-Abgleich ist hier noch nicht für jeden Eintrag abgeschlossen. Der nächste Geräte-Sweep schließt ihn ab, ebenso Jetzt synchronisieren unter Geräte › Anwendungen › Jamf Patch.",
  management: { recurring: "Regelmäßige Update-Prüfung", one_time: "Einmalige Update-Prüfung", observe: "Änderungen beobachten" },
  cadence: (versions, one) => `Fleet hat in den letzten 90 Tagen ${versions} ${one ? "Version" : "Versionen"} dieses Titels datiert; ab zwei empfiehlt sich eine regelmäßige Prüfung.`,
  cadenceUnread: "Wie oft Fleet diesen Titel aktualisiert, ist unbekannt, bis sein Versionsverlauf gelesen ist.", planLink: "Patch-Plan für diese Macs erstellen",
  installedFindings: "Funde in installierten Builds", covered: "Bewertete Builds", uncovered: "Nicht bewertete Builds",
  affected: "Mit Funden", highCritical: "Mit hohen oder kritischen Funden", exploited: "Mit bekannt ausgenutzten Funden",
  findingsLag: "Jeder Mac hält eine eigene Kopie der Antwort zu einem Build, die die stündliche Aktualisierung nachzieht; bis zu einer Stunde nach einer Korpus-Veröffentlichung oder einem Sweep können diese Zahlen daher vom Urteil oben abweichen.",
  observedCount: (changes, oneChange, macs, oneMac, days) =>
    `${changes} ${oneChange ? "erfasster" : "erfasste"} Versionswechsel auf ${macs} ${oneMac ? "Mac" : "Macs"} in den letzten ${days} Tagen.`,
  observedLast: at => `Zuletzt erfasst am ${at}.`, observedTitle: "Nach der Fleet-Veröffentlichung beobachtete Updates",
  observedSource: "Eine 0 kann hier bedeuten, dass das Änderungsprotokoll keine Anwendungen erfasst (Einstellungen › Änderungsverfolgung), und ein Änderungsprotokoll, das kürzer als 90 Tage aufbewahrt wird, zählt nur die aufbewahrten Tage.",
  observedLag: (days, oneDay, pairs, onePair) =>
    `Median ${days} ${oneDay ? "Tag" : "Tage"} nach Fleets Datierung der Version, bei ${pairs} ${onePair ? "Mac/Versions-Paar" : "Mac/Versions-Paaren"}.`,
  observedNoLag: "Kein erfasstes Upgrade auf diesen Macs in diesem Zeitraum ließ sich einer Version zuordnen, die Fleets Verlauf datiert hat.",
  observedNotMeasured: "Der Zeitpunkt von Upgrades wird nur für eine App gemessen, die genau einem Fleet-Titel zugeordnet ist.",
  observedNote: "Aus dem Änderungsprotokoll: Das Intervall endet, wenn ein Sweep das Upgrade auf einem Mac zuerst erfasst hat; wie oft das Inventar erfasst wird, verlängert es.",
  impact: "Zielversion vergleichen", target: "Fleet-Ziel", fetchImpact: "Zielvergleich wird geladen…", resetTarget: "Neueste Fleet-Version verwenden",
  installedScope: "Passende Macs", older: "Unter der Zielversion", atOrAbove: "Auf oder über der Zielversion", chooseFromHistory: "Ein anderes Ziel wählen Sie im Versionsverlauf unten.",
  pinCheck: "Prüfen Sie vor dem Festlegen dieser Version, ob Fleet sie unter Actions › Versions noch anbietet.", impactError: "Dieses Ziel konnte nicht verglichen werden.",
  impactNoReason: "Es kam kein Grund zurück. Versuchen Sie es erneut; scheitert es wieder, zeigt das Protokoll des App-Containers die Anfrage und ihren Fehler.",
  impactUnavailable: (reason, target) => ({
    catalog_incomplete: "Die Geräteauswirkung ist nicht verfügbar: Fleets Katalog ist nicht vollständig gelesen. Sie kehrt nach der nächsten vollständigen Prüfung zurück.",
    no_fleet_title: "Kein Fleet-Titel entspricht der Bundle-Kennung dieser App, daher gibt es kein Ziel zum Vergleichen.",
    identity_review: "Die Geräteauswirkung ist nicht verfügbar, bis die Identität dieser App geprüft ist: Sie hat keine Bundle-Kennung, mehr als ein Fleet-Kanal oder Jamf-Titel passt zu ihr, oder ihre Jamf-Zuordnung ist angenommen.",
    unordered_target: `Die Geräteauswirkung ist nicht verfügbar: Fleets Version ${target} lässt sich nicht gegen installierte Versionen einordnen. Wählen Sie eine Version in Punktnotation aus dem Verlauf unten.`
  } satisfies Record<ImpactUnavailable, string>)[reason],
  findings: "Schwachstellen- und Richtliniennachweise", allPolicy: "Richtlinie über alle installierten Builds", exempt: "Ausgenommen", unassessed: "Ohne Richtlinienurteil",
  scanner: "Die Funde stammen aus der Antwort des Schwachstellen-Korpus für jeden exakten Build, nicht aus einem Scan dieser Macs.",
  findingScope: "Verglichen werden ältere installierte Builds. Jede Zeile vergleicht einen beobachteten Build mit dem gewählten Ziel.",
  noOlder: "Kein vergleichbarer älterer Build im Gerätefilter.", risk: "Funde in der Zielversion", due: date => `Fällig am ${date}`,
  unordered: (builds, one, target) => one
    ? `${builds} installierter Build hat eine Versionsangabe, die sich nicht gegen ${target} einordnen lässt. Er steht unter „Installierte Builds“ und fehlt in dieser Tabelle.`
    : `${builds} installierte Builds haben Versionsangaben, die sich nicht gegen ${target} einordnen lassen. Sie stehen unter „Installierte Builds“ und fehlen in dieser Tabelle.`,
  exactDelta: (addressed, introduced, remaining) => `${addressed} behoben · ${introduced} neu · ${remaining} verbleibend`,
  netDelta: (net, n) => net === 0 ? "Gesamtzahl der Funde unverändert" : `Insgesamt ${n} ${Math.abs(net) === 1 ? "Fund" : "Funde"} ${net > 0 ? "weniger" : "mehr"}`,
  capped: "Die Fund-IDs sind begrenzt. Vergleichbar ist nur die Änderung der Gesamtzahl.", proof: "Fund-IDs prüfen",
  addressed: "In der Zielversion behoben", introduced: "In der Zielversion neu", remaining: "In beiden Builds vorhanden", ambiguousBuild: "Identität muss geprüft werden",
  off: "Korpus nicht verfügbar", unknown_source: "Installierter Build außerhalb des Korpus", unknown_target: "Ziel-Build außerhalb des Korpus",
  kev: n => `Bekannt ausgenutzte Funde im installierten Build: ${n}`, defaultRule: "Standardregel der Organisation", overrideRule: "Titelspezifische Regel",
  policyIdentity: "Nicht beurteilt, bis die Identität dieses Builds geprüft ist: Mehr als ein Fleet- oder Jamf-Titel passt zu ihm, oder seine Jamf-Zuordnung ist angenommen.",
  policyNoTitle: "Nicht beurteilt: Kein Jamf-Patch-Titel passt zu diesem Build."
};
