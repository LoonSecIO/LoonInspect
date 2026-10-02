import type { Refusal, SliderStop } from "@/features/patchPolicy/replay";

/**
 * The words of the patch-policy reference page (#614, first slice), kept beside the feature the way
 * `devices/historyCopy.ts` is, so the views can be lifted out with their copy and no dictionary.
 *
 * Four things these words must keep saying. A release date is *as reported by Jamf's patch catalog*,
 * never *released on*. The replayed count is never called all the CVEs: the excluded ones are named
 * and counted. An app with no replay reads *no reference replay yet*, never zero. And the page is a
 * reference analysis of a hypothetical Mac, never this organization's exposure.
 */
const plural = (count: number, one: string, many: string) => (count === 1 ? one : many);

export const patchPolicyEnglish = {
  eyebrow: "Reference analysis",
  title: "Patch policy",
  description:
    "Pick an app and a patch policy, and read how many of the app's published vulnerabilities a Mac kept to that policy would never have been exposed to.",
  num: (value: number) => value.toLocaleString("en-US"),

  appHeading: "App",
  appSearch: "Search Jamf's patch catalog",
  appHasReplay: "Reference replay",
  appNoReplay: "No reference replay yet",
  appNoMatches: "No app in the list matches that search.",
  appsCapped: (shown: number, total: number) => `Showing ${shown} of ${total} apps. Search to narrow the list.`,
  catalogLoading: "Reading Jamf's patch catalog…",
  catalogEmpty:
    "Jamf's patch catalog holds no titles on this instance yet, so only the apps with a reference replay are listed. It fills on the first catalog refresh of a Jamf Pro connection (Settings › Connections).",
  catalogFailed:
    "Jamf's patch catalog could not be read, so only the apps with a reference replay are listed. That is a failed read, not an empty catalog. Reload the page; if it holds, report it with the build from Settings › Support.",
  unknownApp: (id: string) => `No reference replay is filed under "${id}". Pick an app from the list.`,

  replayLoading: "Loading the reference replay…",
  refusedLead: (name: string) => `The reference replay for ${name} is not shown, because its file was refused.`,
  refused: (refusal: Refusal): string => {
    switch (refusal.why) {
      case "unreadable":
        return "The file did not load, or what loaded is not a replay.";
      case "kind":
        return `Its kind is ${refusal.found}, and this page reads patch_policy_replay only.`;
      case "schema":
        return `Its schema is ${refusal.found}, and this page reads schema 1 only.`;
      case "missing":
        return `It lacks ${refusal.key}, which this page draws.`;
      case "totals":
        return `Its own totals disagree (${refusal.detail}), so no number from it is shown.`;
    }
  },
  refusedCheck:
    "The file ships inside this build and none of this organization's data is involved. Reload once. If it reads the same, report this message with the build from Settings › Support (troubleshooting.md §22).",

  referenceTitle: "A reference analysis, not this organization's exposure",
  reference: (title: string, since: string, until: string) =>
    `One hypothetical Mac that follows Jamf's "${title}" patch title, replayed from ${since} to ${until} against public CVE records. No inventory from this instance is read to draw it, nothing is sent anywhere, and no number here is stored as a measure of this fleet.`,

  policyHeading: "Patch policy",
  stops: { "1d": "1 day", "7d": "7 days", "14d": "14 days", "30d": "30 days", "60d": "60 days", never: "Never" } satisfies Record<SliderStop, string>,
  policySaid: (stop: SliderStop) =>
    stop === "never"
      ? "No release is installed: the Mac stays on the version it opened the window with."
      : `Every release is installed by day ${parseInt(stop, 10)}, where day one is the date Jamf's patch catalog reports for the release.`,

  neverSeenLabel: "vulnerabilities never seen",
  of: "of",
  neverSeenSaid: "Never seen: on or after the day NVD published the CVE, this Mac ran no version the CVE affects.",
  outside: (outside: number, neverSeen: number, line: string | undefined) =>
    `${outside} of the ${neverSeen} never seen were never in range: they affect only versions ${line ? `off the ${line} line` : "this Mac never runs"}, so no policy on this title meets them.`,
  denominators: (replayed: number, inWindow: number, excluded: number) =>
    `${replayed} CVEs were replayed, of ${inWindow} published in the window. The other ${excluded} are excluded and counted below; excluded is not safe.`,

  exposed: "Exposed",
  exposedHint: "CVEs this Mac ran an affected version for, on or after publication",
  exposureDays: "Exposure days",
  exposureDaysHint: "CVE-days, summed over the exposed CVEs",
  updateEvents: "Update events",
  updateEventsHint: "days on which the installed version rises",
  openAtEnd: "Still open at window end",
  openAtEndHint: "exposed CVEs with no fix installed by the last day",
  versions: (initial: string, final: string) => `Opens the window on ${initial} and ends it on ${final}.`,
  installs: (count: number) => `The ${count} ${plural(count, "update", "updates")} this Mac makes`,
  branchChoice: (count: number) =>
    `Following Jamf's combined title instead, which crosses to newer release lines, changes the outcome of ${count} ${plural(count, "CVE", "CVEs")} under this policy.`,

  compareHeading: "Every stop on the slider",
  colPolicy: "Policy",
  colNeverSeen: "Never seen",
  colOutside: "of which never in range",

  ledgerHeading: "Each replayed CVE",
  filterAll: "All",
  filterNeverSeen: "Never seen",
  filterExposed: "Exposed",
  colCve: "CVE",
  colPublished: "Published (NVD)",
  colSeverity: "Severity (today's score)",
  colFix: (line: string | undefined) => `Fix${line ? ` on ${line}` : ""}, as reported by Jamf`,
  fix: (version: string, reported: string | null | undefined) => (reported ? `${version}, reported ${reported}` : version),
  noFixOnLine: "none on this line",
  colOutcome: (stop: string) => `Outcome at ${stop}`,
  outcome: {
    fixFirst: "Never seen: the fix was installed first",
    outsideRange: "Never seen: never in range",
    neverSeen: "Never seen",
    cleared: (days: number, version: string, on: string) => `Exposed ${days} ${plural(days, "day", "days")}, until ${version} on ${on}`,
    open: (days: number) => `Exposed ${days} ${plural(days, "day", "days")}, still open at window end`,
    exposed: "Exposed"
  },
  severity: { critical: "Critical", high: "High", medium: "Medium", low: "Low" } as Record<string, string>,
  unscored: "Not scored",

  exclusionsHeading: (excluded: number) => `Excluded: ${excluded} ${plural(excluded, "CVE", "CVEs")}`,
  exclusionsSaid:
    "Published in the window and left out of every number above, each for one reason. They were not replayed, which is not the same as not affecting this Mac.",
  colReason: "Reason",
  colCount: "CVEs",
  colDetail: "Detail",
  reasons: {
    rejected: "Rejected by the CVE program",
    no_configuration_for_pair: "NVD has not yet listed which versions are affected",
    excluded_platform: "Not about macOS",
    configuration_declined: "The affected-version listing could not be read safely",
    only_prerelease_criteria: "Names only pre-release builds",
    no_fixed_version_determinable: "No fixed version can be read from the record",
    fixed_version_not_in_catalog: "The fixed version is not a release in Jamf's patch catalog",
    branch_ambiguity: "The affected range covers a release line whose fix it does not name"
  } as Record<string, string>,
  excludedList: (excluded: number) => `The ${excluded} excluded ${plural(excluded, "CVE", "CVEs")}`,

  definitionsHeading: "Definitions and clocks, in the file's own words",
  definitions: "Definitions",
  clocks: "Clocks",
  tabledHeading: "Not on the slider",
  tabledSaid:
    "The file also carries a policy that installs a release only when a fix is critical or KEV-listed. It is tabled, so this page shows none of its numbers. Its definition, as the file states it:",

  evidenceHeading: "Evidence",
  evidenceWindow: "Window",
  evidenceCatalog: "Jamf patch catalog snapshot",
  fetched: (when: string) => `fetched ${when}`,
  evidenceRun: "Run",
  releaseDates:
    "Release dates are as reported by Jamf's patch catalog. They are not a claim about when the vendor made a release available."
};

export type PatchPolicyCopy = typeof patchPolicyEnglish;

const mehrzahl = (count: number, one: string, many: string) => (count === 1 ? one : many);

export const patchPolicyGerman: PatchPolicyCopy = {
  eyebrow: "Referenzanalyse",
  title: "Patch-Richtlinie",
  description:
    "Wählen Sie eine App und eine Patch-Richtlinie und lesen Sie, wie vielen veröffentlichten Schwachstellen der App ein Mac, der diese Richtlinie einhält, nie ausgesetzt gewesen wäre.",
  num: (value: number) => value.toLocaleString("de-DE"),

  appHeading: "App",
  appSearch: "Jamfs Patch-Katalog durchsuchen",
  appHasReplay: "Referenz-Replay",
  appNoReplay: "Noch kein Referenz-Replay",
  appNoMatches: "Keine App in der Liste passt zu dieser Suche.",
  appsCapped: (shown: number, total: number) => `${shown} von ${total} Apps angezeigt. Suchen Sie, um die Liste einzugrenzen.`,
  catalogLoading: "Jamfs Patch-Katalog wird gelesen…",
  catalogEmpty:
    "Jamfs Patch-Katalog enthält auf dieser Instanz noch keine Titel; aufgeführt sind daher nur die Apps mit einem Referenz-Replay. Er füllt sich mit der ersten Katalogaktualisierung einer Jamf-Pro-Verbindung (Einstellungen › Verbindungen).",
  catalogFailed:
    "Jamfs Patch-Katalog konnte nicht gelesen werden; aufgeführt sind daher nur die Apps mit einem Referenz-Replay. Das ist ein fehlgeschlagener Lesevorgang, kein leerer Katalog. Laden Sie die Seite neu; bleibt es dabei, melden Sie es mit dem Build aus Einstellungen › Support.",
  unknownApp: (id: string) => `Unter „${id}“ ist kein Referenz-Replay abgelegt. Wählen Sie eine App aus der Liste.`,

  replayLoading: "Referenz-Replay wird geladen…",
  refusedLead: (name: string) => `Das Referenz-Replay für ${name} wird nicht angezeigt, weil seine Datei abgelehnt wurde.`,
  refused: (refusal: Refusal): string => {
    switch (refusal.why) {
      case "unreadable":
        return "Die Datei wurde nicht geladen, oder das Geladene ist kein Replay.";
      case "kind":
        return `Ihr kind ist ${refusal.found}; diese Seite liest nur patch_policy_replay.`;
      case "schema":
        return `Ihr schema ist ${refusal.found}; diese Seite liest nur schema 1.`;
      case "missing":
        return `Ihr fehlt ${refusal.key}, das diese Seite darstellt.`;
      case "totals":
        return `Ihre eigenen Summen stimmen nicht überein (${refusal.detail}); deshalb wird keine Zahl daraus angezeigt.`;
    }
  },
  refusedCheck:
    "Die Datei wird mit diesem Build ausgeliefert, und keine Daten dieser Organisation sind beteiligt. Laden Sie einmal neu. Lautet die Meldung gleich, melden Sie sie mit dem Build aus Einstellungen › Support (troubleshooting.md §22).",

  referenceTitle: "Eine Referenzanalyse, nicht die Exposition dieser Organisation",
  reference: (title: string, since: string, until: string) =>
    `Ein hypothetischer Mac, der Jamfs Patch-Titel „${title}“ folgt, nachgespielt von ${since} bis ${until} gegen öffentliche CVE-Einträge. Dafür wird kein Inventar dieser Instanz gelesen, nichts wird irgendwohin gesendet, und keine Zahl hier wird als Messwert dieser Flotte gespeichert.`,

  policyHeading: "Patch-Richtlinie",
  stops: { "1d": "1 Tag", "7d": "7 Tage", "14d": "14 Tage", "30d": "30 Tage", "60d": "60 Tage", never: "Nie" },
  policySaid: (stop: SliderStop) =>
    stop === "never"
      ? "Kein Release wird installiert: Der Mac bleibt auf der Version, mit der er das Zeitfenster begonnen hat."
      : `Jedes Release ist bis Tag ${parseInt(stop, 10)} installiert; Tag eins ist das Datum, das Jamfs Patch-Katalog für das Release meldet.`,

  neverSeenLabel: "Schwachstellen nie gesehen",
  of: "von",
  neverSeenSaid: "Nie gesehen: Ab dem Tag, an dem NVD die CVE veröffentlicht hat, lief auf diesem Mac keine Version, die sie betrifft.",
  outside: (outside: number, neverSeen: number, line: string | undefined) =>
    `${outside} der ${neverSeen} nie gesehenen waren nie im betroffenen Bereich: Sie betreffen nur Versionen ${line ? `außerhalb der Linie ${line}` : "die dieser Mac nie ausführt"}, sodass keine Richtlinie auf diesem Titel ihnen begegnet.`,
  denominators: (replayed: number, inWindow: number, excluded: number) =>
    `${replayed} CVEs wurden nachgespielt, von ${inWindow} im Zeitfenster veröffentlichten. Die übrigen ${excluded} sind ausgeschlossen und unten gezählt; ausgeschlossen heißt nicht sicher.`,

  exposed: "Exponiert",
  exposedHint: "CVEs, für die dieser Mac ab der Veröffentlichung eine betroffene Version ausführte",
  exposureDays: "Expositionstage",
  exposureDaysHint: "CVE-Tage, summiert über die exponierten CVEs",
  updateEvents: "Update-Ereignisse",
  updateEventsHint: "Tage, an denen die installierte Version steigt",
  openAtEnd: "Am Ende des Zeitfensters noch offen",
  openAtEndHint: "exponierte CVEs, deren Fix bis zum letzten Tag nicht installiert war",
  versions: (initial: string, final: string) => `Beginnt das Zeitfenster auf ${initial} und beendet es auf ${final}.`,
  installs: (count: number) => `${mehrzahl(count, "Das eine Update", `Die ${count} Updates`)}, die dieser Mac ausführt`,
  branchChoice: (count: number) =>
    `Folgt der Mac stattdessen Jamfs kombiniertem Titel, der auf neuere Release-Linien wechselt, ändert sich unter dieser Richtlinie das Ergebnis von ${count} ${mehrzahl(count, "CVE", "CVEs")}.`,

  compareHeading: "Jede Stufe des Reglers",
  colPolicy: "Richtlinie",
  colNeverSeen: "Nie gesehen",
  colOutside: "davon nie im betroffenen Bereich",

  ledgerHeading: "Jede nachgespielte CVE",
  filterAll: "Alle",
  filterNeverSeen: "Nie gesehen",
  filterExposed: "Exponiert",
  colCve: "CVE",
  colPublished: "Veröffentlicht (NVD)",
  colSeverity: "Schweregrad (heutige Bewertung)",
  colFix: (line: string | undefined) => `Fix${line ? ` auf ${line}` : ""}, wie von Jamf gemeldet`,
  fix: (version: string, reported: string | null | undefined) => (reported ? `${version}, gemeldet am ${reported}` : version),
  noFixOnLine: "keiner auf dieser Linie",
  colOutcome: (stop: string) => `Ergebnis bei ${stop}`,
  outcome: {
    fixFirst: "Nie gesehen: Der Fix war zuerst installiert",
    outsideRange: "Nie gesehen: nie im betroffenen Bereich",
    neverSeen: "Nie gesehen",
    cleared: (days: number, version: string, on: string) => `${days} ${mehrzahl(days, "Tag", "Tage")} exponiert, bis ${version} am ${on}`,
    open: (days: number) => `${days} ${mehrzahl(days, "Tag", "Tage")} exponiert, am Ende des Zeitfensters noch offen`,
    exposed: "Exponiert"
  },
  severity: { critical: "Kritisch", high: "Hoch", medium: "Mittel", low: "Niedrig" },
  unscored: "Nicht bewertet",

  exclusionsHeading: (excluded: number) => `Ausgeschlossen: ${excluded} ${mehrzahl(excluded, "CVE", "CVEs")}`,
  exclusionsSaid:
    "Im Zeitfenster veröffentlicht und aus jeder Zahl oben herausgelassen, jeweils aus einem Grund. Sie wurden nicht nachgespielt; das ist nicht dasselbe wie: Sie betreffen diesen Mac nicht.",
  colReason: "Grund",
  colCount: "CVEs",
  colDetail: "Detail",
  reasons: {
    rejected: "Vom CVE-Programm zurückgewiesen",
    no_configuration_for_pair: "NVD hat die betroffenen Versionen noch nicht aufgeführt",
    excluded_platform: "Betrifft nicht macOS",
    configuration_declined: "Die Angabe der betroffenen Versionen ließ sich nicht sicher lesen",
    only_prerelease_criteria: "Nennt nur Vorabversionen",
    no_fixed_version_determinable: "Aus dem Eintrag lässt sich keine korrigierte Version lesen",
    fixed_version_not_in_catalog: "Die korrigierte Version ist kein Release in Jamfs Patch-Katalog",
    branch_ambiguity: "Der betroffene Bereich umfasst eine Release-Linie, deren Fix er nicht nennt"
  },
  excludedList: (excluded: number) => `${mehrzahl(excluded, "Die eine ausgeschlossene CVE", `Die ${excluded} ausgeschlossenen CVEs`)}`,

  definitionsHeading: "Definitionen und Uhren, im Wortlaut der Datei",
  definitions: "Definitionen",
  clocks: "Uhren",
  tabledHeading: "Nicht auf dem Regler",
  tabledSaid:
    "Die Datei enthält außerdem eine Richtlinie, die ein Release nur installiert, wenn ein Fix kritisch oder KEV-gelistet ist. Sie ist zurückgestellt; diese Seite zeigt keine ihrer Zahlen. Ihre Definition, wie die Datei sie angibt:",

  evidenceHeading: "Belege",
  evidenceWindow: "Zeitfenster",
  evidenceCatalog: "Snapshot von Jamfs Patch-Katalog",
  fetched: (when: string) => `abgerufen ${when}`,
  evidenceRun: "Lauf",
  releaseDates:
    "Release-Daten sind die von Jamfs Patch-Katalog gemeldeten. Sie sind keine Aussage darüber, wann der Hersteller ein Release bereitgestellt hat."
};
