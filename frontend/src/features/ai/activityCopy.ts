// AI Activity's own words (#872). The server's verdict, purpose and coverage texts arrive
// already worded and are shown as sent, like the other server diagnostics.
type WorkCounts = { arrivals: string; completed: string; failed: string; cached: string; skipped: string; expired: string; retries: string; fallbacks: string };
type AttemptCounts = { answered: string; unusable: string; waitingTimeouts: string; retries: string; fallbacks: string };

export const aiActivityEnglish = {
  title: "AI Activity",
  intro: "LoonInspect’s AI calls, their purpose, and current workload. Reading this page does not call an AI provider.",
  providerSetup: "Provider setup",
  unknown: "Unknown",
  notMeasured: "Not yet measured",
  measured: (reports: string, attempts: string) => `${reports}/${attempts} attempts measured`,
  errors: {
    invalidDates: "Choose a valid start and end date (UTC).",
    rangeLength: "Choose an inclusive range of 1–90 days. The end must be on or after the start.",
    futureEnd: "The end date cannot be in the future (UTC).",
    forbidden: "You do not have permission to read AI Activity. Ask an administrator for system read access.",
    badFilters: "AI Activity could not read these filters. Check the date range and selected values, then retry.",
    liveUnreadable: "Live workload could not be read. Check connectivity and retry; this does not mean there were no calls.",
    historyUnreadable: "AI history could not be read. Check connectivity and retry; this does not mean there were no calls."
  },
  live: {
    title: "Live workload",
    intro: "Current work across all services · independent of the history filters below.",
    refresh: "Refresh live workload",
    unavailable: "Measurement unavailable",
    reading: "Reading workload…",
    stale: "The last reading is at least 45 seconds old. Refresh to check the workload; its previous health verdict is no longer current.",
    nextCheck: "Next check:",
    lastReading: "Last successful reading",
    asOf: "As of",
    noReading: "No successful reading yet.",
    polling: "Refreshes every 15 seconds",
    paused: "Refresh paused while this tab is hidden",
    waiting: "Waiting", running: "Running", oldestWait: "Oldest wait", noneWaiting: "None waiting",
    arriving: (minutes: number) => `Work arriving (${minutes} min)`,
    completions: (minutes: number) => `Useful completions (${minutes} min)`,
    evidence: "Recent failures, status evidence and coverage",
    window: (from: string, to: string, incomplete: boolean) =>
      `Arrivals and completions: ${from}–${to}${incomplete ? " · incomplete measurement window" : ""}. Waiting and running are current counts.`,
    failures: (failed: string, limited: string, timeouts: string, waitingTimeouts: string, expired: string) =>
      `Recent failures: ${failed} · Rate limits: ${limited} · Request timeouts: ${timeouts} · Waiting timeouts: ${waitingTimeouts} · Expired: ${expired}`,
    inventory: (waiting: string, running: string, oldest: string, disabled: boolean) =>
      `Inventory summaries: ${waiting} waiting, ${running} running, oldest wait ${oldest}${disabled ? " · disabled" : ""}.`,
    interactive: (waiting: string, running: string, oldest: string) => `Interactive requests: ${waiting} waiting, ${running} running, oldest wait ${oldest}.`,
    patch: (active: string, oldest: string) => `Patch investigations: ${active} active, oldest ${oldest} · partial coverage of source research before inference.`,
    detailedSince: (since: string) => `Detailed measurement began: ${since}. Other applications using these providers are outside LoonInspect’s visibility.`,
    coverageLimits: "Coverage limits:",
    recordingIncomplete: (since: string) => `Recording has been incomplete since ${since}. These counts may omit work; check the application diagnostics.`
  },
  history: {
    title: "Historical usage",
    intro: "Inclusive UTC days · finalized attempts in this period, separate from the live workload above.",
    refresh: "Refresh history",
    period: "Historical period",
    days: (days: number) => `${days} days`,
    from: "From (UTC)", through: "Through (UTC)",
    clearFilters: "Clear filters",
    filters: "Filter by service, purpose, model or outcome",
    service: "Service", purpose: "Purpose", model: "Model (requested or reported)", outcome: "Outcome",
    all: "All",
    outside: (value: string) => `${value} (outside this period)`,
    protocolFilter: "Protocol filter", protocol: "Provider protocol",
    protocols: { apple_fm: "Apple Foundation Models", openai_compatible: "OpenAI-compatible protocol (multiple services)", anthropic: "Anthropic" },
    protocolHelp: "An OpenAI-compatible request may go to OpenAI, Ollama or another service. Use Service for actual attribution.",
    reading: "Reading AI history…"
  },
  summary: {
    attempts: "Inference attempts", dispatches: "Provider dispatches", useful: "Useful results", failed: "Failed attempts",
    avgRequest: "Average request time", avgWait: "Average local wait",
    aiDisabled: "AI inference is disabled. Retained historical measurements remain readable.",
    incomplete: "Measurement is incomplete. Recorded calls are shown below, but missing writes mean these totals cannot establish usage or health. Check application diagnostics.",
    usageDisabled: "Usage measurement is disabled. Counts are unavailable; check AI settings.",
    dispatchNote: "An attempt can fail while waiting before dispatch. Dispatch means handed to the HTTP transport; it does not confirm receipt by the provider. Useful results were accepted by the requesting feature; a provider answer alone is not proof of useful work. Missing measurements are unknown, not zero.",
    noCalls: "No inference attempts were recorded in this period.",
    noCallsConfigured: "Check the range or use a configured AI feature.",
    noCallsUnconfigured: "No AI service is configured; open Provider setup to configure one.",
    noMatches: "No attempts match these filters. Clear a filter or choose another period.",
    servicesTitle: "Which services handled the calls?",
    serviceColumns: ["Service at call time", "Attempts / share", "Useful results", "Input tokens", "Output tokens", "Average request"],
    purposesTitle: "What is it doing?",
    attemptCount: (count: string) => `${count} attempts`,
    trendTitle: "Calls over time",
    trendHelp: "Finalized inference attempts by UTC day · select a day to inspect.",
    trendGroup: "Daily inference attempts",
    day: (day: string, count: string) => `${day}: ${count} attempts`,
    total: (count: string) => `${count} total`,
    details: "Work, timing, token coverage and model details",
    workUnmeasured: "Logical work was not measured in this period. Arrivals, completions, cache hits and skips are unknown; daily attempt totals cannot reconstruct them.",
    work: (n: WorkCounts) =>
      `Measured logical work: ${n.arrivals} arrivals · ${n.completed} useful completions · ${n.failed} failures · ${n.cached} cache hits · ${n.skipped} skipped · ${n.expired} expired · ${n.retries} retries · ${n.fallbacks} fallbacks. These are work events, not additional inference calls. A cache hit does not dispatch inference.`,
    workTimes: "Arrivals use arrival time; terminal outcomes use completion time. A job may arrive before this period and finish inside it.",
    partialWork: (since: string) => `Work counts cover only recorded lifecycle events. Measurement began ${since}; legacy records and recording gaps cannot establish missing work.`,
    attemptsLine: (n: AttemptCounts) =>
      `Attempts: ${n.answered} answered · ${n.unusable} unusable · ${n.waitingTimeouts} waiting timeouts · ${n.retries} retries · ${n.fallbacks} fallbacks.`,
    avgTotal: "Average total elapsed", avgProvider: "Average provider-reported execution",
    inputTokens: "Input tokens", outputTokens: "Output tokens", cachedTokens: "Cached tokens",
    durationsNote: "Durations are averages of measured attempts, with separate coverage. Provider execution is reported by the provider. Tokens are reported usage, not a billing estimate.",
    groupColumns: ["Service / purpose", "Requested → reported model", "Outcome", "Attempts", "Dispatched", "Useful", "Input / output / cached tokens", "Average wait / request / total"],
    legacy: "Legacy measurement",
    input: "Input:", output: "Output:", cached: "Cached:", wait: "Wait:", request: "Request:", totalTime: "Total:",
    historyAsOf: (asOf: string, first: string, days: number) => `History as of ${asOf} · first retained daily measurement ${first} · ${days} days retained.`,
    detailed: (since: string, legacy: string, detailed: string) =>
      `Detailed measurement began ${since}. ${legacy} legacy attempts; ${detailed} detailed attempts. Historical service labels stay as recorded; a provider configuration change does not rewrite them.`,
    coverageLimits: "Coverage limits:",
    recordingIncomplete: (since: string) => `Recording has been incomplete since ${since}. Totals may omit calls; check application diagnostics.`
  }
};

export type AIActivityCopy = typeof aiActivityEnglish;

export const aiActivityGerman: AIActivityCopy = {
  title: "KI-Aktivität",
  intro: "Die KI-Aufrufe von LoonInspect, ihr Zweck und die aktuelle Auslastung. Das Lesen dieser Seite ruft keinen KI-Anbieter auf.",
  providerSetup: "Anbieter einrichten",
  unknown: "Unbekannt",
  notMeasured: "Noch nicht gemessen",
  measured: (reports, attempts) => `${reports}/${attempts} Versuche gemessen`,
  errors: {
    invalidDates: "Wählen Sie ein gültiges Start- und Enddatum (UTC).",
    rangeLength: "Wählen Sie einen Zeitraum von 1–90 Tagen einschließlich. Das Ende muss am oder nach dem Start liegen.",
    futureEnd: "Das Enddatum darf nicht in der Zukunft liegen (UTC).",
    forbidden: "Sie dürfen die KI-Aktivität nicht lesen. Bitten Sie einen Administrator um Lesezugriff auf das System.",
    badFilters: "Die KI-Aktivität konnte diese Filter nicht lesen. Prüfen Sie den Zeitraum und die ausgewählten Werte und versuchen Sie es erneut.",
    liveUnreadable: "Die aktuelle Auslastung konnte nicht gelesen werden. Prüfen Sie die Verbindung und versuchen Sie es erneut; das bedeutet nicht, dass es keine Aufrufe gab.",
    historyUnreadable: "Der KI-Verlauf konnte nicht gelesen werden. Prüfen Sie die Verbindung und versuchen Sie es erneut; das bedeutet nicht, dass es keine Aufrufe gab."
  },
  live: {
    title: "Aktuelle Auslastung",
    intro: "Laufende Arbeit über alle Dienste · unabhängig von den Verlaufsfiltern unten.",
    refresh: "Aktuelle Auslastung aktualisieren",
    unavailable: "Messung nicht verfügbar",
    reading: "Auslastung wird gelesen…",
    stale: "Die letzte Messung ist mindestens 45 Sekunden alt. Aktualisieren Sie, um die Auslastung zu prüfen; ihre vorherige Bewertung ist nicht mehr aktuell.",
    nextCheck: "Nächste Prüfung:",
    lastReading: "Letzte erfolgreiche Messung",
    asOf: "Stand",
    noReading: "Noch keine erfolgreiche Messung.",
    polling: "Aktualisiert alle 15 Sekunden",
    paused: "Aktualisierung pausiert, solange dieser Tab verborgen ist",
    waiting: "Wartend", running: "Laufend", oldestWait: "Längste Wartezeit", noneWaiting: "Nichts wartet",
    arriving: minutes => `Eingehende Arbeit (${minutes} Min.)`,
    completions: minutes => `Nützliche Abschlüsse (${minutes} Min.)`,
    evidence: "Letzte Fehler, Statusnachweise und Abdeckung",
    window: (from, to, incomplete) =>
      `Eingänge und Abschlüsse: ${from}–${to}${incomplete ? " · unvollständiges Messfenster" : ""}. Wartend und laufend sind aktuelle Zahlen.`,
    failures: (failed, limited, timeouts, waitingTimeouts, expired) =>
      `Letzte Fehler: ${failed} · Ratenbegrenzungen: ${limited} · Zeitüberschreitungen der Anfrage: ${timeouts} · Zeitüberschreitungen beim Warten: ${waitingTimeouts} · Abgelaufen: ${expired}`,
    inventory: (waiting, running, oldest, disabled) =>
      `Inventar-Zusammenfassungen: ${waiting} wartend, ${running} laufend, längste Wartezeit ${oldest}${disabled ? " · deaktiviert" : ""}.`,
    interactive: (waiting, running, oldest) => `Interaktive Anfragen: ${waiting} wartend, ${running} laufend, längste Wartezeit ${oldest}.`,
    patch: (active, oldest) => `Patch-Untersuchungen: ${active} aktiv, älteste ${oldest} · Quellenrecherche vor der Inferenz nur teilweise erfasst.`,
    detailedSince: since => `Detaillierte Messung seit: ${since}. Andere Anwendungen, die diese Anbieter nutzen, liegen außerhalb der Sicht von LoonInspect.`,
    coverageLimits: "Grenzen der Abdeckung:",
    recordingIncomplete: since => `Die Aufzeichnung ist seit ${since} unvollständig. Diese Zahlen können Arbeit auslassen; prüfen Sie die Anwendungsdiagnose.`
  },
  history: {
    title: "Verlauf der Nutzung",
    intro: "UTC-Tage einschließlich · abgeschlossene Versuche in diesem Zeitraum, getrennt von der aktuellen Auslastung oben.",
    refresh: "Verlauf aktualisieren",
    period: "Zeitraum des Verlaufs",
    days: days => `${days} Tage`,
    from: "Von (UTC)", through: "Bis (UTC)",
    clearFilters: "Filter zurücksetzen",
    filters: "Nach Dienst, Zweck, Modell oder Ergebnis filtern",
    service: "Dienst", purpose: "Zweck", model: "Modell (angefordert oder gemeldet)", outcome: "Ergebnis",
    all: "Alle",
    outside: value => `${value} (außerhalb dieses Zeitraums)`,
    protocolFilter: "Protokollfilter", protocol: "Anbieterprotokoll",
    protocols: { apple_fm: "Apple Foundation Models", openai_compatible: "OpenAI-kompatibles Protokoll (mehrere Dienste)", anthropic: "Anthropic" },
    protocolHelp: "Eine OpenAI-kompatible Anfrage kann an OpenAI, Ollama oder einen anderen Dienst gehen. Für die tatsächliche Zuordnung verwenden Sie „Dienst“.",
    reading: "KI-Verlauf wird gelesen…"
  },
  summary: {
    attempts: "Inferenzversuche", dispatches: "Übergaben an den Anbieter", useful: "Nützliche Ergebnisse", failed: "Fehlgeschlagene Versuche",
    avgRequest: "Mittlere Anfragedauer", avgWait: "Mittlere lokale Wartezeit",
    aiDisabled: "KI-Inferenz ist deaktiviert. Gespeicherte Verlaufsmessungen bleiben lesbar.",
    incomplete: "Die Messung ist unvollständig. Erfasste Aufrufe stehen unten, aber wegen fehlender Schreibvorgänge belegen diese Summen weder Nutzung noch Zustand. Prüfen Sie die Anwendungsdiagnose.",
    usageDisabled: "Die Nutzungsmessung ist deaktiviert. Zahlen sind nicht verfügbar; prüfen Sie die KI-Einstellungen.",
    dispatchNote: "Ein Versuch kann schon beim Warten vor der Übergabe scheitern. Übergabe heißt: an den HTTP-Transport übergeben; der Empfang beim Anbieter ist damit nicht bestätigt. Nützliche Ergebnisse hat die anfragende Funktion angenommen; eine Antwort des Anbieters allein belegt keine nützliche Arbeit. Fehlende Messwerte sind unbekannt, nicht null.",
    noCalls: "In diesem Zeitraum wurden keine Inferenzversuche erfasst.",
    noCallsConfigured: "Prüfen Sie den Zeitraum oder verwenden Sie eine eingerichtete KI-Funktion.",
    noCallsUnconfigured: "Kein KI-Dienst ist eingerichtet; richten Sie unter „Anbieter einrichten“ einen ein.",
    noMatches: "Keine Versuche entsprechen diesen Filtern. Entfernen Sie einen Filter oder wählen Sie einen anderen Zeitraum.",
    servicesTitle: "Welche Dienste haben die Aufrufe bearbeitet?",
    serviceColumns: ["Dienst zum Zeitpunkt des Aufrufs", "Versuche / Anteil", "Nützliche Ergebnisse", "Eingabe-Tokens", "Ausgabe-Tokens", "Mittlere Anfragedauer"],
    purposesTitle: "Wofür wird KI genutzt?",
    attemptCount: count => `${count} Versuche`,
    trendTitle: "Aufrufe im Zeitverlauf",
    trendHelp: "Abgeschlossene Inferenzversuche pro UTC-Tag · wählen Sie einen Tag zur Ansicht.",
    trendGroup: "Tägliche Inferenzversuche",
    day: (day, count) => `${day}: ${count} Versuche`,
    total: count => `${count} gesamt`,
    details: "Arbeit, Zeiten, Token-Abdeckung und Modelldetails",
    workUnmeasured: "Logische Arbeit wurde in diesem Zeitraum nicht gemessen. Eingänge, Abschlüsse, Cache-Treffer und übersprungene Arbeit sind unbekannt; tägliche Versuchssummen können sie nicht rekonstruieren.",
    work: n =>
      `Gemessene logische Arbeit: ${n.arrivals} Eingänge · ${n.completed} nützliche Abschlüsse · ${n.failed} Fehler · ${n.cached} Cache-Treffer · ${n.skipped} übersprungen · ${n.expired} abgelaufen · ${n.retries} Wiederholungen · ${n.fallbacks} Ausweichmodelle. Das sind Arbeitsereignisse, keine zusätzlichen Inferenzaufrufe. Ein Cache-Treffer löst keine Inferenz aus.`,
    workTimes: "Eingänge zählen zum Eingangszeitpunkt, Endergebnisse zum Abschlusszeitpunkt. Ein Auftrag kann vor diesem Zeitraum eingehen und darin abgeschlossen werden.",
    partialWork: since => `Die Arbeitszahlen umfassen nur erfasste Lebenszyklusereignisse. Die Messung begann ${since}; Altdaten und Aufzeichnungslücken können fehlende Arbeit nicht belegen.`,
    attemptsLine: n =>
      `Versuche: ${n.answered} beantwortet · ${n.unusable} unbrauchbar · ${n.waitingTimeouts} Zeitüberschreitungen beim Warten · ${n.retries} Wiederholungen · ${n.fallbacks} Ausweichmodelle.`,
    avgTotal: "Mittlere Gesamtdauer", avgProvider: "Mittlere vom Anbieter gemeldete Ausführung",
    inputTokens: "Eingabe-Tokens", outputTokens: "Ausgabe-Tokens", cachedTokens: "Zwischengespeicherte Tokens",
    durationsNote: "Dauern sind Mittelwerte gemessener Versuche, jeweils mit eigener Abdeckung. Die Ausführungszeit meldet der Anbieter. Tokens sind gemeldete Nutzung, keine Abrechnungsschätzung.",
    groupColumns: ["Dienst / Zweck", "Angefordertes → gemeldetes Modell", "Ergebnis", "Versuche", "Übergeben", "Nützlich", "Eingabe- / Ausgabe- / Cache-Tokens", "Mittlere Wartezeit / Anfrage / Gesamt"],
    legacy: "Altmessung",
    input: "Eingabe:", output: "Ausgabe:", cached: "Cache:", wait: "Warten:", request: "Anfrage:", totalTime: "Gesamt:",
    historyAsOf: (asOf, first, days) => `Verlauf mit Stand ${asOf} · erste erhaltene Tagesmessung ${first} · ${days} Tage Aufbewahrung.`,
    detailed: (since, legacy, detailed) =>
      `Detaillierte Messung seit ${since}. ${legacy} Altversuche; ${detailed} detaillierte Versuche. Historische Dienstnamen bleiben wie erfasst; eine geänderte Anbieterkonfiguration schreibt sie nicht um.`,
    coverageLimits: "Grenzen der Abdeckung:",
    recordingIncomplete: since => `Die Aufzeichnung ist seit ${since} unvollständig. Summen können Aufrufe auslassen; prüfen Sie die Anwendungsdiagnose.`
  }
};
