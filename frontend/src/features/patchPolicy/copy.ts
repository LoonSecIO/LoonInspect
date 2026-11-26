import { REPLAY_SCHEMA, type AffectedRange, type Refusal, type SliderStop } from "@/features/patchPolicy/replay";

/**
 * The words of the patch-policy reference page (#614, first slice), kept beside the feature the way
 * `devices/historyCopy.ts` is, so the views can be lifted out with their copy and no dictionary.
 *
 * Five things these words must keep saying. A release date is the date the file's own timeline gives
 * it, and the page names that timeline from the file (`timeline.name`), never a source of its own and
 * never *released on*. The CVE clock is said: each CVE counts from NVD's publication date, the one
 * clock a file may be on (`readReplay` refuses another). The replayed count is never called all the
 * CVEs: the excluded ones are named and counted. An app with no replay reads *no reference replay
 * yet*, never zero. And the page is a reference analysis of a hypothetical Mac, never this
 * organization's exposure.
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
    "Jamf's patch catalog holds no titles on this instance yet, so only the apps with a reference replay are listed. This instance refreshes it at the top of every hour without a Jamf Pro connection; if it stays empty, see troubleshooting.md §6.",
  catalogFailed:
    "Jamf's patch catalog could not be read, so only the apps with a reference replay are listed. That is a failed read, not an empty catalog. Reload the page; if it holds, report it with the build from Settings › Support.",
  unknownApp: (id: string) => `No reference replay is filed under "${id}". Pick an app from the list.`,
  noReplays:
    "No reference replay ships with this build, so no app can be picked. That is the build, not this organization's data: report it with the build from Settings › Support (troubleshooting.md §22).",

  replayLoading: "Loading the reference replay…",
  refusedLead: (name: string) => `The reference replay for ${name} is not shown, because its file was refused.`,
  refused: (refusal: Refusal): string => {
    switch (refusal.why) {
      case "unreadable":
        return "The file did not load, or what loaded is not a replay.";
      case "kind":
        return `Its kind is ${refusal.found}, and this page reads patch_policy_replay only.`;
      case "schema":
        return refusal.found === "1"
          ? `Its schema is 1, the earlier replay format, which has no timeline block, the part of the file this page reads to name and link where its release dates come from. This page reads schema ${REPLAY_SCHEMA} only.`
          : `Its schema is ${refusal.found}, and this page reads schema ${REPLAY_SCHEMA} only.`;
      case "clock":
        return `Its CVE clock is ${refusal.found}. This page states one CVE clock, NVD's publication date (published), and would misstate any other.`;
      case "missing":
        return `It lacks ${refusal.key}, which this page draws.`;
      case "totals":
        return `Its own totals disagree (${refusal.detail}), so no number from it is shown.`;
    }
  },
  refusedCheck:
    "The file ships inside this build and none of this organization's data is involved. Reload once. If it reads the same, report this message with the build from Settings › Support (troubleshooting.md §22).",

  referenceTitle: "A reference analysis, not this organization's exposure",
  reference: (app: string, line: string | null, since: string, until: string) =>
    `One hypothetical Mac that runs ${app}${line ? `, held on its ${line} release line` : ""}, replayed from ${since} to ${until} against public CVE records. No inventory from this instance is read to draw it, nothing is sent anywhere, and no number here is stored as a measure of this fleet.`,
  // The file's name for its source is printed as a label, never inside a sentence: the file's words
  // cannot be edited to fit one (they may open with "The", or be in another language than the page).
  sources: (timeline: string) =>
    `Release dates: ${timeline}. The CVE clock is NVD's publication date: each CVE counts from the day NVD published it.`,
  releaseChannelOnly: (app: string) =>
    `This replays ${app}'s release channel. ${app} ESR is not replayed yet, though the app list may show it under this row, because the two share a bundle ID.`,
  shortened: (until: string, requested: string | null) =>
    `This replay ends on ${until}, ${requested ? `before the ${requested} it was asked to reach` : "earlier than it was asked to"}: the file cut its window short, and Evidence › Window gives its reason in the file's own words.`,

  policyHeading: "Patch policy",
  stops: { "1d": "1 day", "7d": "7 days", "14d": "14 days", "30d": "30 days", "60d": "60 days", never: "Never" } satisfies Record<SliderStop, string>,
  policySaid: (stop: SliderStop) =>
    stop === "never"
      ? "No release is installed: the Mac stays on the version it opened the window with."
      : `Every release is installed by day ${parseInt(stop, 10)}, where day one is the date the release-date source above gives the release.`,
  waitsForPromotion:
    "A build served before its major version is promoted to stable is installed no earlier than the promotion day, and a major above the promotion table's newest row is not installed (early_stable, under Definitions).",
  promotionTableBehind:
    "The promotion table has no row yet for the newest major version the release-date source above dates, so this Mac never installs that major here.",

  neverSeenLabel: "vulnerabilities never seen",
  of: "of",
  neverSeenSaid: "Never seen: on or after the day NVD published the CVE, this Mac ran no version the CVE affects.",
  outside: (outside: number, neverSeen: number, line: string | null) =>
    `${outside} of the ${neverSeen} never seen ${plural(outside, "was", "were")} never in range: ${plural(outside, "it affects", "they affect")} only versions ${line ? `off the ${line} line` : "this Mac never runs"}, so no patch policy meets ${plural(outside, "it", "them")} here.`,
  /** The never stop, in place of `outside`, in the walk and in the reference replays alike: the device
   *  keeps one version, so its never-seen count is split by why. Those already fixed in that version
   *  are a real never seen; those outside every range NVD names may only be a line NVD stopped
   *  listing (troubleshooting.md §33 step 11). */
  neverStays: (version: string | null, neverSeen: number, outside: number) => {
    const fixed = neverSeen - outside;
    const kept = version ?? "the version it starts the window on";
    const that = version ?? "that version";
    const parts = [`A device that never updates stays on ${kept}.`];
    if (fixed > 0) {
      const whom = fixed === neverSeen ? `${plural(fixed, "The one", `All ${fixed}`)} never seen` : `Of the ${neverSeen} never seen, ${fixed}`;
      parts.push(`${whom} ${plural(fixed, "was", "were")} already fixed in ${that}, so the device never ran a version ${plural(fixed, "it affects", "they affect")}.`);
    }
    if (outside > 0) {
      const whom = fixed > 0 ? plural(outside, "The other one falls", `The other ${outside} fall`) : plural(outside, "The one never seen falls", `All ${outside} never seen fall`);
      parts.push(
        `${whom} outside every range NVD names: either ${plural(outside, "it affects", "they affect")} only other versions, or NVD names no range for ${that}'s line, since NVD often stops naming a line once it reaches end of life. ${plural(outside, "It does", "They do")} not show the device was safe`
      );
    }
    return `${parts.join(" ").replace(/\.$/, "")} (troubleshooting.md §33 step 11).`;
  },
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
    `Following the newest release line instead, which crosses to newer lines as they ship, changes the outcome of ${count} ${plural(count, "CVE", "CVEs")} under this policy.`,

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
  colFix: (line: string | null) => `Fix${line ? ` on ${line}` : ""}, with its release date`,
  fix: (version: string, dated: string | null | undefined) => (dated ? `${version}, dated ${dated}` : version),
  /** NVD's statement a fix closes, printed beside it when a CVE has more than one fix on the line. */
  affected: (range: AffectedRange) =>
    "exact" in range
      ? `for version ${range.exact}`
      : `for versions${range.start ? ` from ${range.start.version} (${range.start.including ? "including" : "excluding"})` : ""}${range.end ? ` up to ${range.end.version} (${range.end.including ? "including" : "excluding"})` : ""}`,
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
    fixed_version_not_in_catalog: "The fixed version is not a release on this replay's release timeline",
    branch_ambiguity: "The affected range covers a release line whose fix it does not name",
    other_edition_only: "NVD lists only another edition (ESR) as affected: no release this channel was shipping when the CVE was published"
  } as Record<string, string>,
  excludedList: (excluded: number) => `The ${excluded} excluded ${plural(excluded, "CVE", "CVEs")}`,
  colStatus: "NVD status when the file was made",

  definitionsHeading: "Definitions and clocks, in the file's own words",
  definitions: "Definitions",
  clocks: "Clocks",
  tabledHeading: "Not on the slider",
  tabledSaid:
    "The file also carries a policy that installs a release only when a fix is critical or KEV-listed. It is tabled, so this page shows none of its numbers. Its definition, as the file states it:",

  evidenceHeading: "Evidence",
  evidenceWindow: "Window",
  asked: (requested: string) => `asked to reach ${requested}`,
  evidenceTimeline: "Release dates",
  fetched: (when: string) => `fetched ${when}`,
  evidenceClock: "CVE clock",
  cveClock: "NVD publication date",
  evidenceRun: "Run",
  releaseDatesSaid:
    "Every release date on this page is a date from that timeline, and the page computes none."
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
    "Jamfs Patch-Katalog enthält auf dieser Instanz noch keine Titel; aufgeführt sind daher nur die Apps mit einem Referenz-Replay. Diese Instanz aktualisiert ihn zu jeder vollen Stunde, ohne Jamf-Pro-Verbindung; bleibt er leer, siehe troubleshooting.md §6.",
  catalogFailed:
    "Jamfs Patch-Katalog konnte nicht gelesen werden; aufgeführt sind daher nur die Apps mit einem Referenz-Replay. Das ist ein fehlgeschlagener Lesevorgang, kein leerer Katalog. Laden Sie die Seite neu; bleibt es dabei, melden Sie es mit dem Build aus Einstellungen › Support.",
  unknownApp: (id: string) => `Unter „${id}“ ist kein Referenz-Replay abgelegt. Wählen Sie eine App aus der Liste.`,
  noReplays:
    "Mit diesem Build wird kein Referenz-Replay ausgeliefert; es lässt sich daher keine App auswählen. Das liegt am Build, nicht an den Daten dieser Organisation: Melden Sie es mit dem Build aus Einstellungen › Support (troubleshooting.md §22).",

  replayLoading: "Referenz-Replay wird geladen…",
  refusedLead: (name: string) => `Das Referenz-Replay für ${name} wird nicht angezeigt, weil seine Datei abgelehnt wurde.`,
  refused: (refusal: Refusal): string => {
    switch (refusal.why) {
      case "unreadable":
        return "Die Datei wurde nicht geladen, oder das Geladene ist kein Replay.";
      case "kind":
        return `Ihr kind ist ${refusal.found}; diese Seite liest nur patch_policy_replay.`;
      case "schema":
        return refusal.found === "1"
          ? `Ihr schema ist 1, das frühere Replay-Format ohne timeline-Block, den Teil der Datei, aus dem diese Seite die Quelle ihrer Release-Daten benennt und verlinkt. Diese Seite liest nur schema ${REPLAY_SCHEMA}.`
          : `Ihr schema ist ${refusal.found}; diese Seite liest nur schema ${REPLAY_SCHEMA}.`;
      case "clock":
        return `Ihre CVE-Uhr ist ${refusal.found}. Diese Seite nennt nur eine CVE-Uhr, das Veröffentlichungsdatum bei NVD (published), und würde jede andere falsch angeben.`;
      case "missing":
        return `Ihr fehlt ${refusal.key}, das diese Seite darstellt.`;
      case "totals":
        return `Ihre eigenen Summen stimmen nicht überein (${refusal.detail}); deshalb wird keine Zahl daraus angezeigt.`;
    }
  },
  refusedCheck:
    "Die Datei wird mit diesem Build ausgeliefert, und keine Daten dieser Organisation sind beteiligt. Laden Sie einmal neu. Lautet die Meldung gleich, melden Sie sie mit dem Build aus Einstellungen › Support (troubleshooting.md §22).",

  referenceTitle: "Eine Referenzanalyse, nicht die Exposition dieser Organisation",
  reference: (app: string, line: string | null, since: string, until: string) =>
    `Ein hypothetischer Mac, auf dem ${app} läuft${line ? `, gehalten auf der Release-Linie ${line}` : ""}, nachgespielt von ${since} bis ${until} gegen öffentliche CVE-Einträge. Dafür wird kein Inventar dieser Instanz gelesen, nichts wird irgendwohin gesendet, und keine Zahl hier wird als Messwert dieser Flotte gespeichert.`,
  sources: (timeline: string) =>
    `Release-Daten: ${timeline}. Die CVE-Uhr ist das Veröffentlichungsdatum bei NVD: Jede CVE zählt ab dem Tag, an dem NVD sie veröffentlicht hat.`,
  releaseChannelOnly: (app: string) =>
    `Nachgespielt wird der Release-Kanal von ${app}. ${app} ESR wird noch nicht nachgespielt, auch wenn die App-Liste es unter dieser Zeile führen kann, weil beide dieselbe Bundle-ID haben.`,
  shortened: (until: string, requested: string | null) =>
    `Dieses Replay endet am ${until}, ${requested ? `vor dem angefragten ${requested}` : "früher als angefragt"}: Die Datei hat ihr Zeitfenster gekürzt, und Belege › Zeitfenster nennt den Grund im Wortlaut der Datei.`,

  policyHeading: "Patch-Richtlinie",
  stops: { "1d": "1 Tag", "7d": "7 Tage", "14d": "14 Tage", "30d": "30 Tage", "60d": "60 Tage", never: "Nie" },
  policySaid: (stop: SliderStop) =>
    stop === "never"
      ? "Kein Release wird installiert: Der Mac bleibt auf der Version, mit der er das Zeitfenster begonnen hat."
      : `Jedes Release ist bis Tag ${parseInt(stop, 10)} installiert; Tag eins ist das Datum, das die oben genannte Quelle der Release-Daten dem Release gibt.`,
  waitsForPromotion:
    "Ein Build, der vor der Beförderung seiner Hauptversion zu Stable ausgeliefert wurde, wird frühestens am Tag der Beförderung installiert, und eine Hauptversion oberhalb der neuesten Zeile der Beförderungstabelle wird nicht installiert (early_stable, unter Definitionen).",
  promotionTableBehind:
    "Die Beförderungstabelle hat noch keine Zeile für die neueste Hauptversion, die die oben genannte Quelle der Release-Daten datiert; dieser Mac installiert diese Hauptversion hier daher nie.",

  neverSeenLabel: "Schwachstellen nie gesehen",
  of: "von",
  neverSeenSaid: "Nie gesehen: Ab dem Tag, an dem NVD die CVE veröffentlicht hat, lief auf diesem Mac keine Version, die sie betrifft.",
  outside: (outside: number, neverSeen: number, line: string | null) =>
    `${outside} der ${neverSeen} nie gesehenen ${mehrzahl(outside, "war", "waren")} nie im betroffenen Bereich: ${mehrzahl(outside, "Sie betrifft", "Sie betreffen")} nur Versionen${line ? ` außerhalb der Linie ${line}` : ", die dieser Mac nie ausführt"}, sodass ${mehrzahl(outside, "ihr", "ihnen")} hier keine Patch-Richtlinie begegnet.`,
  neverStays: (version: string | null, neverSeen: number, outside: number) => {
    const fixed = neverSeen - outside;
    const kept = version ?? "der Version, mit der es das Zeitfenster beginnt";
    const that = version ?? "dieser Version";
    const parts = [`Ein Gerät, das nie aktualisiert, bleibt auf ${kept}.`];
    if (fixed > 0) {
      const whom =
        fixed === neverSeen ? mehrzahl(fixed, "Die eine nie gesehene war", `Alle ${fixed} nie gesehenen waren`) : `Von den ${neverSeen} nie gesehenen ${mehrzahl(fixed, "war 1", `waren ${fixed}`)}`;
      parts.push(`${whom} in ${that} bereits behoben; auf dem Gerät lief also nie eine Version, die ${mehrzahl(fixed, "sie betrifft", "sie betreffen")}.`);
    }
    if (outside > 0) {
      const whom =
        fixed > 0 ? mehrzahl(outside, "Die übrige liegt", `Die übrigen ${outside} liegen`) : mehrzahl(outside, "Die eine nie gesehene liegt", `Alle ${outside} nie gesehenen liegen`);
      parts.push(
        `${whom} außerhalb jedes Bereichs, den NVD nennt: Entweder ${mehrzahl(outside, "betrifft sie", "betreffen sie")} nur andere Versionen, oder NVD nennt keinen Bereich für ${version ? `die Linie von ${version}` : "die Linie dieser Version"}, denn NVD führt eine Linie oft nicht mehr auf, sobald sie das Ende ihres Supports erreicht hat. ${mehrzahl(outside, "Sie zeigt", "Sie zeigen")} nicht, dass das Gerät sicher war`
      );
    }
    return `${parts.join(" ").replace(/\.$/, "")} (troubleshooting.md §33 Schritt 11).`;
  },
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
    `Folgt der Mac stattdessen der neuesten Release-Linie, die mit jeder neuen Linie wechselt, ändert sich unter dieser Richtlinie das Ergebnis von ${count} ${mehrzahl(count, "CVE", "CVEs")}.`,

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
  colFix: (line: string | null) => `Fix${line ? ` auf ${line}` : ""}, mit seinem Release-Datum`,
  fix: (version: string, dated: string | null | undefined) => (dated ? `${version}, datiert ${dated}` : version),
  affected: (range: AffectedRange) =>
    "exact" in range
      ? `für Version ${range.exact}`
      : `für Versionen${range.start ? ` ab ${range.start.version} (${range.start.including ? "einschließlich" : "ausschließlich"})` : ""}${range.end ? ` bis ${range.end.version} (${range.end.including ? "einschließlich" : "ausschließlich"})` : ""}`,
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
    fixed_version_not_in_catalog: "Die korrigierte Version ist kein Release auf der Release-Zeitleiste dieses Replays",
    branch_ambiguity: "Der betroffene Bereich umfasst eine Release-Linie, deren Fix er nicht nennt",
    other_edition_only: "NVD führt nur eine andere Edition (ESR) als betroffen: kein Release, das dieser Kanal bei Veröffentlichung der CVE auslieferte"
  },
  excludedList: (excluded: number) => `${mehrzahl(excluded, "Die eine ausgeschlossene CVE", `Die ${excluded} ausgeschlossenen CVEs`)}`,
  colStatus: "NVD-Status bei Erstellung der Datei",

  definitionsHeading: "Definitionen und Uhren, im Wortlaut der Datei",
  definitions: "Definitionen",
  clocks: "Uhren",
  tabledHeading: "Nicht auf dem Regler",
  tabledSaid:
    "Die Datei enthält außerdem eine Richtlinie, die ein Release nur installiert, wenn ein Fix kritisch oder KEV-gelistet ist. Sie ist zurückgestellt; diese Seite zeigt keine ihrer Zahlen. Ihre Definition, wie die Datei sie angibt:",

  evidenceHeading: "Belege",
  evidenceWindow: "Zeitfenster",
  asked: (requested: string) => `angefragt bis ${requested}`,
  evidenceTimeline: "Release-Daten",
  fetched: (when: string) => `abgerufen ${when}`,
  evidenceClock: "CVE-Uhr",
  cveClock: "Veröffentlichungsdatum bei NVD",
  evidenceRun: "Lauf",
  releaseDatesSaid:
    "Jedes Release-Datum auf dieser Seite ist ein Datum aus dieser Zeitleiste; die Seite berechnet keines."
};
