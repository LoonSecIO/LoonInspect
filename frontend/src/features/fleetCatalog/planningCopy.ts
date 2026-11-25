import type { BriefingCode } from "./briefing";
import type { MigrationScope, PriorityReason } from "./migrationTypes";
import type { CoverageKey, PolicySummary, PortfolioEmpty, PortfolioSort, ReviewFilter } from "./portfolioView";

// The migration list's words (#903). Its answer carries codes and counts, never a sentence, so they are worded here,
// the German typed against the English through `Translations`. The list borrows only main's `fleetCatalog.eyebrow`, `title` and
// `emptyFlagOff`, and shows an error's `detail`, the one server sentence, as sent. Each code map `satisfies` its
// union, so a new member fails the type check until both languages word it. No sentence names the list or a
// segment: each next check is named by something on main that keeps its name, which planningCopy.test.ts holds.

/** `n` grouped the reader's way, its noun singular at 1: "1 build", "1,234 builds", "1.234 Builds". */
const english = (n: number, one: string, many: string) => `${n.toLocaleString("en")} ${n === 1 ? one : many}`;
const german = (n: number, one: string, many: string) => `${n.toLocaleString("de")} ${n === 1 ? one : many}`;

export const fleetPlanningEnglish = {
  scope: {
    selectedMacs: "Macs in scope", eligibleMacs: "Current Jamf Macs",
    unknownContactMacs: "Last contact unknown", unknownInventoryMacs: "Last inventory unknown"
  } satisfies Record<keyof MigrationScope, string>,
  filters: {
    all: "All installed apps", candidates: "Patch candidates", overdue: "Out of policy", exposure: "Vulnerability review",
    channels: "Confirm channel", outside: "Outside both catalogs", recurring: "Recurring patch review",
    oneTime: "One-time patch review", unknown: "Missing evidence"
  } satisfies Record<ReviewFilter, string>,
  sorts: { priority: "Patch priority", reach: "Most installed", age: "Oldest open patch gap", name: "App name" } satisfies Record<PortfolioSort, string>,
  coverage: {
    outside: "Outside both catalogs", fleet: "Fleet", channels: "Confirm channel", jamf: "Jamf Patch",
    noFleet: "No Fleet title", unavailable: "Coverage unknown"
  } satisfies Record<CoverageKey, string>,
  // `overdue`, `within` and `unassessed` are main's Jamf Patch legend: the same judgement, under the same rule.
  policy: {
    overdue: "Out of policy", partial: "Partly judged", unassessed: "Not judged", within: "Within policy", exempt: "Exempt"
  } satisfies Record<PolicySummary, string>,
  // Against Fleet's latest version, the list's only target; the app page's header reuses them. The out-of-policy
  // build is not called an older one: the patch rule judges every build, so the one out of policy can be at or
  // past Fleet's latest while another build is behind (#897).
  reasons: {
    out_of_policy: "An installed build is outside its confirmed Jamf Patch rule.",
    kev: "An older installed build carries a finding on CISA’s Known Exploited Vulnerabilities list.",
    comparable: "An older installed build can be compared with Fleet’s latest version.",
    identity: "Overlapping Fleet or Jamf titles, or a release channel assumed from an extension attribute, need review before an update is chosen.",
    unordered: "Some installed versions cannot be ordered against Fleet’s latest version.",
    none_behind: "No installed build in the device filter is older than Fleet’s latest version."
  } satisfies Record<PriorityReason, string>,
  // Which kind of empty, in the order `portfolioEmpty` checks them (docs/diagnosability.md rule 1).
  empty: {
    noSweep: "No current Jamf Mac is on record for the filter’s Jamf connection, so there is nothing to review. Apps appear here once a device sweep collects a Mac.",
    noMacs: "No Mac matches the device filter. Widen or clear the filter.",
    noApps: "The Macs in the device filter have no installed apps on record. Installed Apps, with the same filter, shows what their last sweep collected.",
    noMatch: "No installed app matches this search and Show choice. Clear the search or choose All installed apps."
  } satisfies Record<PortfolioEmpty, string>,
  // The Fleet catalog tab's two views (#904): this list, by the name #893 ruled, and main's Fleet titles.
  segments: { review: "Migration review", titles: "Fleet titles" },
  columns: { app: "Installed app", macs: "Macs", coverage: "Catalog coverage", policy: "Patching policy", findings: "Vulnerability evidence" },
  search: "Find an app or bundle ID",
  show: "Show",
  sortBy: "Sort by",
  unknownCount: "Unknown",
  browse: "Search all Fleet titles",
  retry: "Retry",
  previous: "Previous",
  next: "Next",
  asOf: "Report calculated",
  prevalence: "Share of in-scope Macs",
  loading: "Loading the selected inventory…",
  countsNote: "Counts measure installations. A Mac can have more than one app.",
  range: (first: number, last: number, total: number) =>
    `${first.toLocaleString("en")}–${last.toLocaleString("en")} of ${english(total, "app", "apps")}`,
  builds: (n: number) => english(n, "build", "builds"),
  kev: (n: number) => `KEV on ${english(n, "installed build", "installed builds")}`,
  affected: (n: number) => `${english(n, "installed build", "installed builds")} with findings`,
  unassessedBuilds: (n: number) => `${english(n, "installed build", "installed builds")} not assessed`,
  addressed: (n: number) => `${english(n, "finding", "findings")} addressed at target`,
  gapAge: (days: number) => `Newer Jamf release available for ${english(days, "day", "days")}`,
  clean: "No findings in assessed builds",
  zero: "No addressed findings in evaluated builds",
  missing: "No exact comparison",
  loadFailed: "The installed apps for this device filter could not be read. Check connectivity and retry; this does not mean no app needs review.",
  partialCatalog: "Fleet’s catalog was read only in part, so a title or release channel may be missing. The Fleet catalog’s status line says why.",
  notRead: "Fleet coverage is unknown: Fleet’s catalog has not been read yet. The Fleet catalog’s status line says why.",
  noJamf: "Jamf Patch coverage is unknown: no Jamf Patch titles are synced yet, so no app is counted as outside both catalogs. Open Devices › Applications › Jamf Patch and press Sync now.",
  outsideNote: "Both catalogs are fully read, and neither lists these apps’ bundle IDs.",
  // The migration briefing (#911): codes and counts in, so each lead and line is worded here. `name` goes into main's
  // `changes.prompt.statusFailed`; a refusal's `detail` is shown as sent.
  briefing: {
    name: "the migration briefing",
    title: "Migration briefing",
    disclosure: "Generate briefing sends up to seven counts for the Macs in the device filter, and no app, version or Mac name, to the provider picked here. It chooses up to three to lead with. Nothing is stored.",
    provider: "Provider and model",
    generate: "Generate briefing",
    pending: "Preparing briefing…",
    selected: (who: string) => `${who} chose these counts to lead with.`,
    unusable: (who: string) => `${who} answered, but not with counts this page can use, so the report’s first counts are shown.`,
    error: (why: string) => `The AI provider did not answer, so the report’s first counts are shown (${why}). Settings › AI has its test box.`,
    nothingToRank: "Nothing to rank: apart from their count, the Macs in the device filter show none of the six things a briefing weighs, so nothing was sent.",
    failed: (reason: string) => `The migration briefing could not be prepared: ${reason}. Check docker compose logs app.`,
    codes: {
      apps_overdue: n => `${english(n, "app", "apps")} with an installed build outside the confirmed Jamf Patch rule.`,
      apps_with_kev: n => `${english(n, "app", "apps")} with an older installed build carrying a KEV-listed finding.`,
      ambiguous_apps: n => `${english(n, "app", "apps")} with a Fleet identity that needs review.`,
      incomplete_comparisons: n => `${english(n, "app", "apps")} with an older build lacking an exact finding comparison.`,
      recurring_review: n => `${english(n, "app", "apps")} with an observed gap and repeated Fleet catalog updates.`,
      exact_candidates: n => `${english(n, "app", "apps")} with an exact Fleet catalog candidate.`,
      scoped_macs: n => `${english(n, "Mac", "Macs")} in the device filter.`
    } satisfies Record<BriefingCode, (count: number) => string>
  }
};

export type FleetPlanningCopy = typeof fleetPlanningEnglish;

export const fleetPlanningGerman: FleetPlanningCopy = {
  scope: {
    selectedMacs: "Macs im Gerätefilter", eligibleMacs: "Aktuelle Jamf-Macs",
    unknownContactMacs: "Letzter Kontakt unbekannt", unknownInventoryMacs: "Letzte Inventarisierung unbekannt"
  },
  filters: {
    all: "Alle installierten Apps", candidates: "Patch-Kandidaten", overdue: "Außerhalb der Richtlinie", exposure: "Schwachstellen prüfen",
    channels: "Kanal bestätigen", outside: "In keinem der Kataloge", recurring: "Regelmäßige Patch-Prüfung",
    oneTime: "Einmalige Patch-Prüfung", unknown: "Fehlende Nachweise"
  },
  sorts: { priority: "Patch-Priorität", reach: "Meiste Installationen", age: "Älteste offene Patch-Lücke", name: "App-Name" },
  coverage: {
    outside: "In keinem der Kataloge", fleet: "Fleet", channels: "Kanal bestätigen", jamf: "Jamf Patch",
    noFleet: "Kein Fleet-Titel", unavailable: "Abdeckung unbekannt"
  },
  policy: {
    overdue: "Außerhalb der Richtlinie", partial: "Teilweise beurteilt", unassessed: "Nicht beurteilt",
    within: "Innerhalb der Richtlinie", exempt: "Ausgenommen"
  },
  reasons: {
    out_of_policy: "Ein installierter Build liegt außerhalb seiner bestätigten Jamf-Patch-Regel.",
    kev: "Ein älterer installierter Build hat einen Fund auf CISAs Liste bekannter ausgenutzter Schwachstellen (KEV).",
    comparable: "Ein älterer installierter Build kann mit Fleets neuester Version verglichen werden.",
    identity: "Überschneidende Fleet- oder Jamf-Titel oder ein aus einem Erweiterungsattribut angenommener Kanal müssen geprüft werden, bevor ein Update gewählt wird.",
    unordered: "Einige installierte Versionen lassen sich nicht gegen Fleets neueste Version einordnen.",
    none_behind: "Kein installierter Build im Gerätefilter ist älter als Fleets neueste Version."
  },
  empty: {
    noSweep: "Für die Jamf-Verbindung des Filters ist kein aktueller Jamf-Mac erfasst, daher gibt es nichts zu prüfen. Apps erscheinen hier, sobald ein Sweep einen Mac erfasst.",
    noMacs: "Kein Mac entspricht dem Gerätefilter. Erweitern oder entfernen Sie den Filter.",
    noApps: "Für die Macs im Gerätefilter sind keine installierten Apps erfasst. „Installierte Apps“ zeigt mit demselben Filter, was ihr letzter Sweep erfasst hat.",
    noMatch: "Keine installierte App passt zu dieser Suche und Anzeige. Leeren Sie die Suche oder wählen Sie „Alle installierten Apps“."
  },
  segments: { review: "Migrationsprüfung", titles: "Fleet-Titel" },
  columns: { app: "Installierte App", macs: "Macs", coverage: "Katalogabdeckung", policy: "Patch-Richtlinie", findings: "Schwachstellennachweise" },
  search: "App oder Bundle-ID suchen",
  show: "Anzeigen",
  sortBy: "Sortieren nach",
  unknownCount: "Unbekannt",
  browse: "Alle Fleet-Titel durchsuchen",
  retry: "Erneut versuchen",
  previous: "Zurück",
  next: "Weiter",
  asOf: "Bericht berechnet",
  prevalence: "Anteil an den Macs im Gerätefilter",
  loading: "Ausgewähltes Inventar wird geladen…",
  countsNote: "Die Zahlen erfassen Installationen. Ein Mac kann mehrere Apps enthalten.",
  range: (first, last, total) => `${first.toLocaleString("de")}–${last.toLocaleString("de")} von ${german(total, "App", "Apps")}`,
  builds: n => german(n, "Build", "Builds"),
  kev: n => `KEV in ${german(n, "installierten Build", "installierten Builds")}`,
  affected: n => `${german(n, "installierter Build", "installierte Builds")} mit Funden`,
  unassessedBuilds: n => `${german(n, "installierter Build", "installierte Builds")} nicht bewertet`,
  addressed: n => `${german(n, "Fund", "Funde")} in der Zielversion behoben`,
  gapAge: days => `Neuere Jamf-Version seit ${german(days, "Tag", "Tagen")} verfügbar`,
  clean: "Keine Funde in bewerteten Builds",
  zero: "Keine behobenen Funde in den bewerteten Builds",
  missing: "Kein exakter Vergleich",
  loadFailed: "Die installierten Apps für diesen Gerätefilter konnten nicht gelesen werden. Prüfen Sie die Verbindung und versuchen Sie es erneut; das bedeutet nicht, dass keine App geprüft werden muss.",
  partialCatalog: "Fleets Katalog wurde nur teilweise gelesen, daher können Titel oder Kanäle fehlen. Die Statuszeile des Fleet-Katalogs nennt den Grund.",
  notRead: "Die Fleet-Abdeckung ist unbekannt: Fleets Katalog wurde noch nicht gelesen. Die Statuszeile des Fleet-Katalogs nennt den Grund.",
  noJamf: "Die Jamf-Patch-Abdeckung ist unbekannt: Es sind noch keine Jamf-Patch-Titel synchronisiert, daher zählt keine App als „In keinem der Kataloge“. Öffnen Sie Geräte › Anwendungen › Jamf Patch und klicken Sie auf Jetzt synchronisieren.",
  outsideNote: "Beide Kataloge sind vollständig gelesen, und keiner führt die Bundle-IDs dieser Apps.",
  briefing: {
    name: "die Migrationsübersicht",
    title: "Migrationsübersicht",
    disclosure: "Übersicht erstellen sendet bis zu sieben Zahlen zu den Macs im Gerätefilter an den hier gewählten Anbieter, aber keine App, keine Version und keinen Mac-Namen. Er wählt bis zu drei davon aus, die zuerst genannt werden. Nichts wird gespeichert.",
    provider: "Anbieter und Modell",
    generate: "Übersicht erstellen",
    pending: "Übersicht wird erstellt…",
    selected: who => `${who} hat diese Zahlen an den Anfang gestellt.`,
    unusable: who => `${who} hat geantwortet, aber nicht mit Zahlen, die diese Seite verwenden kann, daher stehen hier die ersten Zahlen des Berichts.`,
    error: why => `Der KI-Anbieter hat nicht geantwortet, daher stehen hier die ersten Zahlen des Berichts (${why}). Unter Einstellungen › KI gibt es das Testfeld.`,
    nothingToRank: "Nichts zu gewichten: Abgesehen von ihrer Anzahl zeigen die Macs im Gerätefilter keinen der sechs Punkte, die eine Übersicht abwägt, daher wurde nichts gesendet.",
    failed: reason => `Die Migrationsübersicht konnte nicht erstellt werden: ${reason}. Prüfen Sie docker compose logs app.`,
    codes: {
      apps_overdue: n => `${german(n, "App", "Apps")} mit einem installierten Build außerhalb der bestätigten Jamf-Patch-Regel.`,
      apps_with_kev: n => `${german(n, "App", "Apps")} mit einem älteren installierten Build, der einen Fund aus der KEV-Liste trägt.`,
      ambiguous_apps: n => `${german(n, "App", "Apps")} mit einer Fleet-Identität, die geprüft werden muss.`,
      incomplete_comparisons: n => `${german(n, "App", "Apps")} mit einem älteren Build ohne exakten Fundvergleich.`,
      recurring_review: n => `${german(n, "App", "Apps")} mit einer beobachteten Lücke und wiederholten Updates im Fleet-Katalog.`,
      exact_candidates: n => `${german(n, "App", "Apps")} mit einem exakten Kandidaten im Fleet-Katalog.`,
      scoped_macs: n => `${german(n, "Mac", "Macs")} im Gerätefilter.`
    }
  }
};
