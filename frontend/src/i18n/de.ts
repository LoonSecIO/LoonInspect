import type { Translations } from "@/i18n/en";

export const de: Translations = {
  system: {
    updateAvailable: "Ein neuerer Build von LoonInspect ist verfügbar",
    dismissUpdate: "Update-Hinweis ausblenden",
    sharing: {
      pageDescription:
        "Die Patch- und Schwachstellen-Feeds, die LoonInspect aufbaut, entstehen aus anonymem Community-Inventar. Was diese Instanz beiträgt — und ob überhaupt — wird hier festgelegt.",
      envLocked:
        "COMMUNITY_SHARING=false ist in der Umgebung gesetzt. Unabhängig von der Auswahl unten wird nichts geteilt; diese Einstellungen sind gesperrt, bis die Vorgabe entfernt wird.",
      tierHeading: "Teilnahme",
      tierReveal: "Teilen und verbreitete Titel offenlegen (empfohlen)",
      tierRevealHelp:
        "Täglich anonyme Inventarschlüssel mit Installationszahlen. App-Namen werden nur offengelegt, wenn LoonSec nach einem Titel fragt, der bei mindestens 5 unabhängigen Teilnehmern vorkommt — interne, firmenspezifische Apps werden nie offengelegt.",
      tierKeys: "Nur Schlüssel teilen",
      tierKeysHelp:
        "Täglich anonyme Inventarschlüssel mit Installationszahlen. Anfragen nach App-Namen werden nie beantwortet — es wird ausschließlich Verbreitungssignal beigetragen.",
      tierOff: "Aus",
      tierOffHelp:
        "Es wird nichts geteilt, und diese Instanz wird die aus der Community aufgebauten Patch- und Schwachstellen-Feeds nicht erhalten, wenn sie erscheinen.",
      disclosureHeading: "Was geteilt wird",
      disclosureShared:
        "Täglich pro Tenant geteilt: Content-Hash-Schlüssel installierter Anwendungen mit Installationszahlen, OS-Versions-Tupel (Hardware-Modell-Tupel sind reserviert und werden leer gesendet), die pseudonyme Übermittlungs-ID unten und die Build-Version dieses Containers. Zahlen werden vor dem Versand über Geräte summiert — nie einzelne Gerätezeilen.",
      disclosureNever:
        "Nie geteilt: Gerätekennungen, Seriennummern, Hostnamen, Benutzernamen, Dateipfade, Extension Attributes, Verbindungs- oder Tenant-Namen, Konten, Zugangsdaten oder Audit-Historie. LoonSec speichert auf diesem Pfad keine Quell-IP-Adressen.",
      disclosureReveals:
        "App-Namen verlassen diese Instanz nur als Antwort auf eine ausdrückliche Anfrage zu einem Titel, der bereits bei 5+ unabhängigen Teilnehmern vorkommt (nur Stufe „Offenlegen“). Diese Schwelle ist LoonSecs veröffentlichte Regel; sie ist von dieser Seite aus nicht überprüfbar — dafür gibt es die Nur-Schlüssel-Stufe.",
      disclosurePseudonym:
        "Übermittlungen sind pseudonym, nicht anonym: Snapshots dieses Tenants sind über die Übermittlungs-ID miteinander verknüpfbar (so ersetzen erneute Übermittlungen ältere, statt doppelt gezählt zu werden). Die ID ist zufällig, an nichts gebunden und unten zurücksetzbar.",
      previewHeading: "Genau das, was gesendet würde",
      previewHelp:
        "Zeigt die wörtliche nächste Übertragung aus den Live-Daten dieser Instanz — über denselben Codepfad wie der tägliche Austausch.",
      previewButton: "Payload anzeigen",
      identityHeading: "Übermittlungsidentität",
      identityHelp:
        "Die Zufalls-ID, mit der LoonSec den vorherigen Snapshot dieses Tenants ersetzt, statt ihn doppelt zu zählen. Ein Zurücksetzen trennt die Verbindung zu allem zuvor Gesendeten.",
      resetUuid: "Zurücksetzen",
      excludeHeading: "Ausgeschlossene Bundle-IDs",
      excludeHelp:
        "Glob-Muster, eines pro Zeile. Passende Anwendungen gelangen nie in einen Snapshot — gefiltert vor der Aggregation, vor jeder serverseitigen Regel.",
      lastExchange: "Letzter Austausch",
      neverExchanged: "nie — bisher wurde kein Austausch aufgezeichnet",
      revealsShed: "Reveals verworfen — der Server lehnte die vollständige Übermittlung ab und nahm einen Wiederholungsversuch ohne Reveals an",
      logHeading: "Freigabeprotokoll",
      logHelp: "Jeder Austauschversuch mit der wörtlichen Payload, die der Lauf zusammengestellt hat — byte-genaue Historie dessen, was diese Instanz verlassen hat. Eine mit revealsShed markierte Zeile hat alles aus ihrer Payload gesendet außer den Reveals. 90 Tage aufbewahrt.",
      downloadLog: "Herunterladen (NDJSON)",
      loadFailed: "Datenfreigabe-Einstellungen konnten nicht geladen werden.",
      saveFailed: "Speichern fehlgeschlagen. Berechtigungen prüfen und erneut versuchen."
    }
  },
  common: {
    darkMode: "Dunkelmodus",
    lightMode: "Hellmodus",
    language: "Sprache",
    sidebar: "Seitenleiste",
    sidebarExpanded: "Symbole + Text",
    sidebarCollapsed: "Nur Symbole",
    sidebarHidden: "Ausgeblendet",
    computersOnlyScope: "Nur Computer — mobile Geräte werden nicht erfasst.",
    opensInNewTab: "(wird in einem neuen Tab geöffnet)"
  },
  auth: {
    versionLabel: "Version",
    loading: "Wird geladen…",
    loginTitle: "Anmelden",
    loginDescription: "Melden Sie sich bei Ihrer LoonInspect-Instanz an.",
    email: "E-Mail",
    password: "Passwort",
    signIn: "Anmelden",
    signingIn: "Anmeldung läuft…",
    signOut: "Abmelden",
    invalidCredentials: "E-Mail oder Passwort ist ungültig.",
    lockedOut: "Zu viele Fehlversuche. Warten Sie einige Minuten und versuchen Sie es erneut.",
    genericError: "Etwas ist schiefgelaufen. Bitte versuchen Sie es erneut.",
    setupTitle: "LoonInspect einrichten",
    setupDescription: "Erstellen Sie das erste Administratorkonto für diese Instanz.",
    claimToken: "Freischaltcode",
    claimTokenHelp: "Wird beim Start in die Container-Logs geschrieben. Abrufen mit:",
    displayName: "Anzeigename",
    passwordHelp: "Mindestens 12 Zeichen. Keine weiteren Zusammensetzungsregeln.",
    createAdmin: "Administrator erstellen",
    creating: "Wird erstellt…",
    invalidClaimToken: "Dieser Freischaltcode ist ungültig.",
    sharingChoice:
      "Anonyme App-, OS- und Hardware-Verbreitung zu den Community-Patch- und Schwachstellen-Feeds beitragen. Nur aggregierte Zahlen und Content-Hashes — nie Geräte-, Benutzer- oder firmenidentifizierende Daten. Jederzeit einsehbar unter Einstellungen \u2192 Datenfreigabe.",
    setupAlreadyDone: "Diese Instanz wurde bereits eingerichtet. Bitte melden Sie sich an.",
    passwordTooShort: "Das Passwort muss mindestens 12 Zeichen lang sein.",
    validationFailed:
      "Einige dieser Angaben wurden nicht akzeptiert. Bitte prüfen Sie das Formular und versuchen Sie es erneut.",
    loginSupportTitle: "Sie können sich nicht anmelden?",
    loginSupportBody:
      "Eine Administratorin oder ein Administrator dieser Instanz kann ein Passwort zurücksetzen oder ein Konto prüfen — das ist der schnellste Weg. Wirkt die Instanz selbst fehlerhaft und nicht nur Ihr Konto, stehen beide Support-Kanäle allen offen.",
    loginSupportWarning:
      "Keiner von beiden ist vertraulich: Fügen Sie dort niemals ein Passwort, ein Token oder einen Sicherheitsfund ein.",
    loginSupportGithub: "Issue auf GitHub anlegen",
    loginSupportSlack: (channel: string) => `In ${channel} auf MacAdmins Slack fragen`,
    noAccessTitle: "Sie haben keinen Zugriff auf diese Seite",
    noAccessDescription:
      "Die Rolle Ihres Kontos umfasst keine Berechtigung für diesen Bereich. Wenden Sie sich an eine Administratorin oder einen Administrator, falls Sie ihn benötigen."
  },
  errors: {
    notFoundTitle: "Diese Seite gibt es nicht",
    notFoundDescription:
      "Unter dieser Adresse liefert LoonInspect nichts aus. Vermutlich ein Tippfehler oder ein Link aus einem älteren Build.",
    notFoundPathLabel: "Angeforderte Adresse",
    backToOverview: "Zurück zur Übersicht",
    crashTitle: "Diese Ansicht konnte nicht dargestellt werden",
    crashDescription:
      "Beim Aufbau der Seite ist ein Fehler aufgetreten. Ihre Sitzung ist davon unberührt und es wurden keine Daten geändert — laden Sie die Seite neu oder kehren Sie zur Übersicht zurück.",
    crashDetailNote:
      "Die technischen Details stehen in der Browser-Konsole. Sie werden hier bewusst nicht angezeigt: Ein Render-Fehler kann Fragmente der Daten dieser Instanz enthalten.",
    reload: "Seite neu laden"
  },
  nav: {
    overview: "Übersicht",
    devices: "Geräte",
    applications: "Anwendungen",
    smartGroupCost: "Gruppenkosten",
    settings: "Einstellungen",
    connections: "Verbindungen",
    featureFlags: "Feature-Flags",
    dataSharing: "Datenfreigabe",
    ai: "KI",
    apiTokens: "API-Token",
    accounts: "Konten",
    myAccount: "Mein Konto",
    destinations: "Ziele",
    changes: "Änderungen",
    changeTracking: "Änderungsverfolgung",
    support: "Support"
  },
  destinations: {
    title: "Ziele",
    description:
      "Wohin Inventar-Ereignisse zugestellt werden – ein SIEM, ein Ingestion-Endpunkt für ein Data Warehouse oder ein beliebiger HTTPS-Webhook. Jedes aktivierte Ziel erhält eine Kopie jedes Ereignisses, das es abonniert hat, mit automatischer Wiederholung bei Fehlern.",
    add: "Ziel hinzufügen",
    name: "Name",
    type: "Typ",
    typeGenericWebhook: "Allgemeiner Webhook",
    typeSplunkHec: "Splunk HTTP Event Collector",
    typeElastic: "Elasticsearch",
    typeRunReveal: "RunReveal",
    url: "URL",
    urlHintSplunk:
      "Der vollständige HEC-Endpunkt einschließlich des Pfads /services/collector – standardmäßig Port 8088. Das Geheimnis unten ist das HEC-Token, und der Index ist derjenige, in den dieses Token schreibt.",
    urlHintElastic: "Basis-URL des Clusters – Ereignisse werden über die Bulk-API per POST an {url}/{index}/_bulk gesendet.",
    urlHintRunReveal: "Die Ingest-URL der RunReveal-Webhook-Quelle, zu finden unter „Source Details“.",
    elasticIndex: "Index",
    elasticIndexHint:
      "Index oder Data Stream, in den geschrieben wird. Leer lassen für den Standard, den Elastics eingebautes logs-*-*-Template ohne weitere Einrichtung akzeptiert.",
    elasticApiKey: "API-Schlüssel",
    elasticApiKeyRotate: "Neuer API-Schlüssel",
    elasticApiKeyHint: "Der Base64-Schlüssel, den Elastic einmalig beim Erstellen anzeigt – gesendet als Authorization: ApiKey.",
    authType: "Authentifizierung",
    authNone: "Keine",
    authBearer: "Bearer-Token",
    authHeader: "Benutzerdefinierter Header",
    authHeaderName: "Header-Name",
    authSecret: "Geheimnis",
    authSecretRotate: "Neues Geheimnis",
    authSecretPlaceholder: "Leer lassen, um das aktuelle Geheimnis beizubehalten",
    enabled: "Aktiviert",
    enabledLabel: "Aktiviert",
    disabledLabel: "Deaktiviert",
    save: "Speichern",
    saving: "Wird gespeichert…",
    cancel: "Abbrechen",
    edit: "Bearbeiten",
    enable: "Aktivieren",
    disable: "Deaktivieren",
    delete: "Löschen",
    deleteConfirm: "Dieses Ziel löschen?",
    confirm: "Bestätigen",
    tableName: "Name",
    tableType: "Typ",
    tableUrl: "URL",
    tableStatus: "Status",
    tableLastActivity: "Letzte Aktivität",
    neverDelivered: "Noch nichts zugestellt",
    lastFailed: (when: string) => `Fehlgeschlagen ${when}`,
    test: "Testen",
    testing: "Test läuft…",
    testDelivered: "Zugestellt — das Ziel hat ein Testereignis angenommen.",
    testRefused: (detail: string) => `Testzustellung abgelehnt: ${detail}`,
    errorTesting: "Test konnte nicht ausgeführt werden. Das Ziel war gar nicht erreichbar.",
    pendingDeliveries: (count: number) => `${count} in Warteschlange`,
    failedDeliveries: (count: number) => `${count} aufgegeben`,
    loading: "Ziele werden geladen…",
    empty: "Noch keine Ziele konfiguriert.",
    errorLoading: "Ziele konnten nicht geladen werden.",
    errorCreating: "Das Ziel konnte nicht erstellt werden.",
    errorUpdating: "Das Ziel konnte nicht aktualisiert werden.",
    errorDeleting: "Das Ziel konnte nicht gelöscht werden."
  },
  accounts: {
    title: "Konten",
    description: "Personen, die sich bei LoonInspect anmelden können. Nicht zu verwechseln mit den Personen, denen in Jamf Geräte zugeordnet sind.",
    addAccount: "Konto hinzufügen",
    displayName: "Anzeigename",
    email: "E-Mail",
    initialPassword: "Initiales Passwort",
    passwordHint:
      "Mindestens 12 Zeichen. Es gibt keinen E-Mail-Versand – geben Sie es selbst weiter. Es kann unter „Mein Konto“ geändert werden.",
    roles: "Rollen",
    create: "Konto erstellen",
    creating: "Wird erstellt…",
    cancel: "Abbrechen",
    tableName: "Name",
    tableRoles: "Rollen",
    tableStatus: "Status",
    tableLastLogin: "Letzte Anmeldung",
    active: "Aktiv",
    disabled: "Deaktiviert",
    disable: "Deaktivieren",
    enable: "Aktivieren",
    resetPassword: "Passwort zurücksetzen",
    newPassword: "Neues Passwort",
    confirm: "Bestätigen",
    you: "Sie",
    breakGlass: "Notfallzugang",
    breakGlassHint: "Behält die lokale Anmeldung auch dann, wenn einmal ein Identitätsanbieter verpflichtend wird (heute ist keiner konfiguriert). Jede Anmeldung dieses Kontos wird mit hoher Priorität protokolliert.",
    cannotDisableSelf: "Sie können Ihr eigenes Konto nicht deaktivieren.",
    disableHint:
      "Beim Deaktivieren werden Sitzungen und API-Token sofort widerrufen. Konten werden nie gelöscht, damit frühere Audit-Einträge zuordenbar bleiben.",
    loading: "Konten werden geladen…",
    errorLoading: "Konten konnten nicht geladen werden.",
    errorCreating: "Das Konto konnte nicht erstellt werden.",
    errorUpdating: "Das Konto konnte nicht aktualisiert werden.",
    errorResetting: "Das Passwort konnte nicht zurückgesetzt werden."
  },
  myAccount: {
    title: "Mein Konto",
    description: "Ihr Profil und Passwort.",
    name: "Name",
    email: "E-Mail",
    roles: "Rollen",
    build: "Build",
    changePassword: "Passwort ändern",
    changing: "Wird geändert…",
    currentPassword: "Aktuelles Passwort",
    newPassword: "Neues Passwort",
    confirmPassword: "Neues Passwort bestätigen",
    changed: "Passwort geändert.",
    mismatch: "Die neuen Passwörter stimmen nicht überein.",
    wrongCurrent: "Ihr aktuelles Passwort ist falsch.",
    errorChanging: "Das Passwort konnte nicht geändert werden.",
    sessionsHint:
      "Beim Ändern des Passworts werden Ihre anderen Sitzungen abgemeldet. API-Token bleiben gültig – widerrufen Sie diese bei Bedarf separat."
  },
  support: {
    title: "Support",
    description:
      "Zwei Stellen, an denen Sie Hilfe zu LoonInspect bekommen — und eine Sache, die an keine von beiden gehört. Nichts hier erstellt ein Ticket für Sie: LoonInspect wird selbst gehostet, und einen Bericht schreiben und senden Sie selbst.",
    buildHeading: "Beginnen Sie mit dem laufenden Build",
    buildHelp:
      "Der Build-String dieser Instanz. Fügen Sie ihn in alles ein, was Sie schreiben — er ist das Erste, wonach jede Person fragen muss, die einen Bericht liest, und er entscheidet zwischen einer Antwort und einer Rückfrage.",
    buildUnavailable:
      "Noch nicht gelesen. Bleibt das Feld leer, konnte dieser Browser das Backend nicht erreichen — schreiben Sie das in Ihren Bericht und nennen Sie stattdessen das deployte Image-Tag.",
    copy: "Kopieren",
    copied: "Kopiert",
    githubHeading: "GitHub",
    githubBody: (repo: string) =>
      `Fehler, Fragen und Feature-Wünsche gehören in den Issue-Tracker unter ${repo}. Sehen Sie zuerst die offenen Issues durch — bei einem dokumentierten Problem steht der Workaround oft daneben — und legen Sie dann eines an, wenn Ihres nicht dabei ist.`,
    githubInclude:
      "Ein brauchbarer Bericht besteht aus dem Build-String oben, dem erwarteten Verhalten, dem tatsächlichen Verhalten und dem Weg dorthin. Lassen Sie Gerätenamen, Seriennummern, Hostnamen und E-Mail-Adressen weg. Ein Screenshot von LoonInspect besteht zum großen Teil genau daraus: Die Geräteliste zeigt Hostnamen und Seriennummern, und Ihr eigener Name steht in der Kopfleiste. Schneiden Sie diese Stellen weg oder schwärzen Sie sie, bevor Sie einen Screenshot anhängen.",
    githubBrowse: "Issues durchsehen",
    githubOpen: "Issue anlegen",
    slackHeading: "MacAdmins Slack",
    slackBody: (channel: string) =>
      `${channel} ist der Community-Kanal: wie andere etwas eingerichtet haben, ob ein Verhalten erwartbar ist, und die Fragen, die noch kein Fehlerbericht sind. Ein Gespräch, keine Warteschlange — es hat niemand Bereitschaft.`,
    slackSignupNote: (channel: string) =>
      `MacAdmins Slack ist eine eigenständige Community mit eigener Anmeldung. Sind Sie bereits in diesem Workspace, öffnet der Kanal-Link ${channel} direkt. Falls nicht, treten Sie zuerst bei — allein bringt der Kanal-Link Sie nicht hinein.`,
    slackJoin: "MacAdmins Slack beitreten",
    slackOpenChannel: (channel: string) => `${channel} öffnen`,
    securityHeading: "Eine Schwachstelle gefunden? Melden Sie sie vertraulich.",
    securityBody:
      "Ein Sicherheitsfund gehört nie in ein öffentliches Issue. Melden Sie ihn vertraulich über GitHubs private Vulnerability-Meldung in diesem Repository — Security → Report a vulnerability. Das erreicht die Maintainerin oder den Maintainer direkt und hält die Meldung nicht öffentlich, während ein Fix vorbereitet wird.",
    securityFallback: (email: string, channel: string) =>
      `Steht Ihnen dieses Formular nicht zur Verfügung, schreiben Sie stattdessen an ${email}. Auch nicht an ${channel}: dort kann jede Person im Workspace mitlesen.`,
    securityReport: "Schwachstelle vertraulich melden",
    securityPolicy: "Sicherheitsrichtlinie lesen",
    privacyNote:
      "Diese Seite sendet nichts nach außen. Sie liest den Build-String Ihrer eigenen Instanz und zeigt sechs Links nach außen; es gibt keine Telemetrie darauf, und kein Bericht verlässt diesen Browser, sofern Sie ihn nicht selbst schreiben."
  },
  apiTokens: {
    title: "API-Token",
    description:
      "Persönliche Token für Clients außerhalb des Browsers – Skripte, CI und native Clients. Ein Token kann nie mehr als Ihr Konto.",
    name: "Name",
    namePlaceholder: "macOS-Client auf meinem Laptop",
    expiry: "Läuft ab in (Tagen)",
    expiryPlaceholder: "Leer lassen für kein Ablaufdatum",
    scopes: "Berechtigungen",
    scopesHint:
      "Nichts auswählen, um die Berechtigungen Ihres Kontos zu übernehmen. Eine Auswahl schränkt das Token darauf ein.",
    create: "Token erstellen",
    creating: "Wird erstellt…",
    createdTitle: "Token erstellt",
    createdWarning: "Kopieren Sie es jetzt – es wird nur dieses eine Mal angezeigt.",
    copy: "Kopieren",
    copied: "Kopiert",
    dismiss: "Fertig",
    tableName: "Name",
    tableScopes: "Berechtigungen",
    tableCreated: "Erstellt",
    tableExpires: "Läuft ab",
    tableLastUsed: "Zuletzt verwendet",
    revoke: "Widerrufen",
    revoking: "Wird widerrufen…",
    inheritAll: "Übernimmt Konto",
    never: "Nie",
    loading: "Token werden geladen…",
    empty: "Noch keine Token.",
    errorLoading: "Token konnten nicht geladen werden.",
    errorCreating: "Das Token konnte nicht erstellt werden.",
    errorRevoking: "Das Token konnte nicht widerrufen werden."
  },
  overview: {
    eyebrow: "LoonInspect",
    title: "Übersicht",

    setupEyebrow: "Erste Schritte",
    setupTitle: "Bringen Sie Ihre Flotte nach Splunk",
    promise: "Ihr Flotteninventar: 40.000 Geräte in etwa 10 Minuten.",
    stepLabel: (step: number) => `Schritt ${step}`,
    stepOptional: "Optional",
    stepDone: "Erledigt",
    step1Title: "Jamf Pro verbinden",
    step1Body: "Richten Sie LoonInspect auf Ihren Jamf-Pro-Server und hinterlegen Sie API-Zugangsdaten mit Lesezugriff.",
    step1Action: "Verbindung hinzufügen",
    step2Title: "Erste Synchronisierung starten",
    step2Body:
      "Der erste Durchlauf holt alle Geräte, Gruppen und Anwendungen in diesen Pod. Er wird zur Basislinie, an der jede spätere Änderung gemessen wird.",
    step2Action: "Erste Synchronisierung starten",
    step3Title: "An Splunk senden",
    step3Body:
      "Fügen Sie ein Splunk-HEC-Ziel hinzu, dann wird alles, was LoonInspect erfasst, sofort weitergeleitet. Das können Sie auch später tun.",
    step3Action: "Ziel hinzufügen",

    firstSyncTitle: "Erste Synchronisierung läuft",
    syncTitle: "Synchronisierung läuft",
    syncFailedTitle: "Synchronisierung fehlgeschlagen",
    elapsedLabel: "Vergangen",
    devicesLabel: "Geräte",
    groupsLabel: "Gruppen",
    engineLog: "Engine-Protokoll",
    openConnection: "Verbindung öffnen",

    baselineEstablished: (utc: string) => `Basislinie erstellt ${utc}`,
    runPrefix: "Durchlauf",
    baselineCounts: (devices: number, groups: number, duration: string) =>
      `${devices.toLocaleString("de-DE")} Gerät${devices === 1 ? "" : "e"}, ` +
      `${groups.toLocaleString("de-DE")} Gruppe${groups === 1 ? "" : "n"} in ${duration}`,
    seeYourFleet: "Zur Geräteliste",

    // Handlungsbedarf (#106): die Aufgabenliste und die datierte Entwarnungszeile, die
    // die Zusicherung des Produkts ist, wenn nichts darauf steht. Alles hier bleibt eine
    // Vorlage – die grüne Zeile schreibt niemals eine KI (docs/v-never.md).
    attention: {
      title: "Handlungsbedarf",
      loading: "Wird geprüft…",
      allClear: (clock: string) => `Nichts erfordert Ihre Aufmerksamkeit · geprüft ${clock}`,
      checked: (clock: string) => `geprüft ${clock}`,
      // Alle Prüfungen verweigert. Weder Entwarnung noch Fehler — und ohne Uhrzeit: die
      // grüne Zeile trägt einen Zeitstempel, weil sie etwas bezeugt; hier wurde nichts
      // geprüft, also gibt es nichts zu datieren.
      blindTitle: "Nicht geprüft.",
      blindBody:
        "Ihre Rolle hat keinen Zugriff auf Verbindungen, Ziele und Systemstatus — daher wurde keine dieser Prüfungen ausgeführt. Das ist keine Entwarnung. Eine Administratorin oder ein Administrator kann die nötigen Berechtigungen erteilen.",
      kinds: {
        run_failed: "Synchronisierung fehlgeschlagen",
        destination_failing: "Zustellungen schlagen fehl",
        // Nicht „Nie gestartet“: das las sich als Aussage über die gesamte Laufzeit der
        // Sammlung. `next_due_at` wird beim Anfordern weitergestellt — passiert ist
        // also, dass niemand sie abgeholt hat.
        collection_overdue: "Nichts hat sie gestartet",
        inventory_stale: "Inventar ist veraltet",
        update_available: "Ein neuerer Build ist verfügbar",
        // #101. „Neue App“ und nicht „nicht genehmigte App“: bekannt ist nur, dass der
        // Mac sie beim letzten Inventar nicht hatte — über eine Genehmigung weiß das
        // Produkt nichts. Name der App und Mac stehen daneben.
        new_app: "Neue App installiert"
      },
      // Der zusammengefasste Eintrag: ein ausgefallener Tick lässt binnen einer Stunde
      // jede aktivierte Sammlung überfällig werden, und fünf Zeilen mit fünf Namen
      // benennen nichts, was man reparieren kann.
      schedulerStalled: (count: number) =>
        `${count} Sammlungen wurden fällig und nichts hat sie gestartet — bitte die Zeitplanung prüfen`,
      // Der zusammengefasste Eintrag für veraltetes Inventar (#106, entschieden am
      // 2026-09-04): Veralten ist bauartbedingt korreliert — eine Zugangsberechtigung,
      // ein Netzwerkpfad, eine Zeitplanung für alle Sammlungen. Fünf Zeilen mit fünf
      // Namen belegten die ganze Liste, um eine einzige Tatsache zu wiederholen. Benannt
      // wird deshalb die Verbindung, nicht die Sammlungen.
      inventoryStalled: (count: number) =>
        `${count} Sammlungen haben die Flotte seit dem Doppelten ihres eigenen Zeitplans nicht gelesen — bitte die Verbindung prüfen`,
      // Der zusammengefasste Eintrag für fehlgeschlagene Durchläufe (#106, entschieden am
      // 2026-09-04). Dritte Anwendung derselben Regel: Auch hier ist die Ursache
      // bauartbedingt geteilt — eine Zugangsberechtigung, ein Netzwerkpfad, eine
      // Zeitplanung. Fünf Namen verdrängten sonst „Zustellungen schlagen fehl“ aus der
      // Liste, denn ein gerade ausgefallenes Ziel ist immer der jüngste Eintrag im
      // Bereich. Benannt wird deshalb die Verbindung, nicht die Sammlungen.
      syncsFailing: (count: number) =>
        `${count} Sammlungen sind bei ihrer letzten Synchronisierung fehlgeschlagen — bitte die Verbindung prüfen`,
      checkNames: {
        run_failed: "letzte Durchläufe",
        destination_failing: "Ziele",
        collection_overdue: "Zeitpläne der Sammlungen",
        inventory_stale: "Aktualität des Inventars",
        update_available: "Aktualisierungen",
        new_app: "neue Anwendungen"
      },
      couldNotCheck: (what: string) => `${what} konnten nicht geprüft werden`,
      // Die Fußzeile einer gekürzten Liste: N *zusätzlich* zu den fünf angezeigten.
      //
      // Nicht mehr „… erfordern Aufmerksamkeit“: das versprach einen Posteingang, den es
      // nicht gibt — in v0 ist keine Alarmseite vorgesehen (#101). Die Zahl mischt zudem
      // gekappte Zeilen aller Art mit ungeladenen Latches, hat also gar kein einzelnes
      // Ziel, auf das sie verweisen könnte.
      andMore: (count: number) =>
        `${count} ${count === 1 ? "weiterer Eintrag" : "weitere Einträge"}, nicht angezeigt`,
      // Die Beschriftung der Kennzahl in der Seitenleiste — bewusst nicht `andMore`:
      // hier ist die Zahl die ganze Liste, nicht deren Rest.
      badge: (count: number) =>
        `${count} ${count === 1 ? "Eintrag erfordert" : "Einträge erfordern"} Aufmerksamkeit`
    },

    // Die Statuszeile (#105). Eine Zeile pro Verbindung, nennt nur Tatsachen und wird
    // nie rot — eine überschrittene Schwelle ist ein Eintrag unter „Handlungsbedarf“
    // (#106), keine Farbe hier. Jede relative und jede Pluralform ist eine Funktion:
    // Deutsch stellt die Relation voran („vor 2 Std.“), eine im Bauteil angehängte
    // Endung ergäbe „2 Std. vor“.
    strip: {
      identity: (name: string, host: string) => `${name} (${host})`,
      devices: (n: number) => `${n.toLocaleString("de-DE")} Gerät${n === 1 ? "" : "e"}`,
      // Nicht „0 Geräte“: eine Verbindung ohne Sync-Status hat nicht null Geräte
      // gemessen, sondern noch gar nichts.
      noInventoryYet: "noch kein Inventar",
      inventoryAsOf: (utc: string, age: string) => `Inventar vom ${utc} (${age})`,
      agoNow: "gerade eben",
      agoMinutes: (n: number) => `vor ${n} Min.`,
      agoHours: (n: number) => `vor ${n} Std.`,
      agoDays: (n: number) => `vor ${n} ${n === 1 ? "Tag" : "Tagen"}`,
      fullSweep: "vollständiger Durchlauf",
      // Der Plural von „Durchlauf“ ist „Durchläufe“, nicht „Durchlaufe“ — eine
      // angehängte Endung reicht hier nicht, das Wort bekommt einen Umlaut.
      webhookSweepsSince: (n: number) => `+${n} Webhook-${n === 1 ? "Durchlauf" : "Durchläufe"} seitdem`,
      noFullSweepYet: "noch kein vollständiger Durchlauf",
      copied: "Job-ID kopiert",
      nextSweep: (when: string) => `nächster Durchlauf ${when}`,
      noScheduledSweep: "kein Durchlauf geplant",
      sweepsPaused: "Durchläufe pausiert",
      destinationOk: (name: string, utc: string) => `${name} OK ${utc}`,
      destinationLastDelivered: (name: string, utc: string) => `${name} zuletzt zugestellt ${utc}`,
      destinationNothingYet: (name: string) => `${name} noch nichts zugestellt`,
      loadError: "Der Verbindungsstatus konnte nicht geladen werden."
    },

    // Der Änderungs-Feed (#107). Der Bezugspunkt ist browser-lokal, der genannte
    // Zeitpunkt jedoch absolut und steht wörtlich in der Kopfzeile und in jedem Link.
    feed: {
      title: "Seit Ihrem letzten Besuch",
      loading: "Änderungen werden geladen\u2026",
      loadError: "Der Änderungs-Feed konnte nicht geladen werden.",
      summary: (changes: number, devices: number, since: string, notable: number) =>
        `${changes} ${changes === 1 ? "Änderung" : "Änderungen"} auf ${devices} ${devices === 1 ? "Gerät" : "Geräten"} seit ${since} (${notable} relevant)`,
      emptyAfterBaseline: "Basislinie erstellt \u2014 Änderungen erscheinen ab dem nächsten Sync.",
      emptyQuiet: "Keine relevanten Änderungen in diesem Zeitraum.",
      seeAll: "Alle Änderungen anzeigen"
    },

    loading: "Wird geladen…",
    loadError: "Der Einrichtungsstatus konnte nicht geladen werden.",
    setupHiddenForRole: "Die Einrichtung dieses Pods wird von einer Administratorin oder einem Administrator verwaltet."
  },
  devices: {
    eyebrow: "Inventar",
    title: "Geräte",
    searchPlaceholder: "Hostname oder Seriennummer suchen...",
    osVersionPrefix: "Betriebssystemversion",
    osVersionOperators: {
      eq: "ist",
      lt: "älter als",
      lte: "gleich oder älter als",
      gt: "neuer als",
      gte: "gleich oder neuer als",
      regex: "entspricht Regex"
    },
    osVersionPlaceholder: "z. B. 14.5",
    osVersionRegexPlaceholder: "Regex, z. B. ^14\\.",
    sitePlaceholder: "Standort",
    buildingPlaceholder: "Gebäude",
    departmentPlaceholder: "Abteilung",
    managed: "Verwaltet",
    supervised: "Überwacht",
    any: "Alle",
    yes: "Ja",
    no: "Nein",
    tableHostname: "Hostname",
    tableSerial: "Seriennummer",
    tableOsVersion: "Betriebssystemversion",
    tableSite: "Standort",
    tableDepartment: "Abteilung",
    tableManaged: "Verwaltet",
    tableSupervised: "Überwacht",
    tableLastCheckIn: "Letzte Anmeldung",
    loading: "Lädt...",
    errorLoading: "Geräte konnten nicht geladen werden.",
    empty: "Keine Geräte entsprechen diesen Filtern.",
    total: (n: number) => `${n} Gerät${n === 1 ? "" : "e"} insgesamt`,
    pageOf: (page: number, pages: number) => `Seite ${page} von ${pages}`,
    previous: "Zurück",
    next: "Weiter"
  },
  applications: {
    eyebrow: "Geräte",
    title: "Anwendungen",
    description: "Über Ihre Flotte installierte Anwendungen, aggregiert aus dem synchronisierten Geräteinventar.",
    tabInstalled: "Installierte Apps",
    tableName: "Name",
    tableBundleId: "Bundle-ID",
    tableVersion: "Version",
    tableInstalls: "Installationen",
    tableCompliant: "Konform",
    tablePatchAvailable: "Patch verfügbar",
    tableDevices: "Geräte",
    tableVersions: "Versionen",
    tableShortVersion: "Kurzversion",
    tableVersionHash: "Versions-Hash",
    searchPlaceholder: "Nach Name oder Bundle-ID filtern…",
    loading: "Anwendungen werden geladen…",
    errorLoading: "Anwendungen konnten nicht geladen werden.",
    empty: "Noch keine Anwendungen erkannt.",
    total: (n: number) => `${n} Anwendung${n === 1 ? "" : "en"} insgesamt`
  },
  catalog: {
    tabLabel: "Katalog",
    description:
      "Jede App und Version, die die Flotte gezeigt hat, wann sie zuerst und zuletzt auf einem Gerät gesehen wurde und was der Jamf-Patch-Katalog dazu sagt.",
    summaryEntries: "Unterschiedliche App-Versionen",
    summaryInstalled: "Aktuell installiert",
    summaryMatched: "Jamf bekannt",
    summaryUnmatched: "Nicht im Jamf-Katalog",
    searchPlaceholder: "Nach Name, Bundle-ID, Version oder Jamf-Titel filtern…",
    filterAll: "Alle",
    filterMatched: "Jamf bekannt",
    filterUnmatched: "Nicht im Jamf-Katalog",
    installedOnly: "Nur aktuell installierte",
    tableName: "Name",
    tableBundleId: "Bundle-ID",
    tableVersion: "Version",
    tableDevices: "Geräte",
    tableFirstSeen: "Zuerst gesehen",
    tableLastSeen: "Zuletzt gesehen",
    tableJamfTitle: "Jamf-Titel",
    tableState: "Status",
    tableLatest: "Neueste",
    tableReleased: "Veröffentlicht",
    stateLatest: "Aktuell",
    stateBehind: "Veraltet",
    stateAhead: "Dem Katalog voraus",
    stateUnknown: "Unbekannter Build",
    behindSince: (since: string, missed: number | null) =>
      missed === null ? `seit ${since}` : `seit ${since} · ${missed} ${missed === 1 ? "Version" : "Versionen"} verpasst`,
    loading: "Katalog wird geladen…",
    errorLoading: "Der Katalog konnte nicht geladen werden.",
    empty: "Noch keine Apps katalogisiert – der Katalog füllt sich, sobald Geräte verarbeitet werden.",
    noMatches: "Keine Zeilen entsprechen diesem Filter.",
    filteredTotal: (shown: number, total: number) =>
      shown === total ? `${total} Zeile${total === 1 ? "" : "n"}` : `${shown} von ${total} Zeilen`,
    tableVuln: "Schwachstellen"
  },
  vulnerabilities: {
    corpusHeading: (date: string) => `Schwachstellen-Korpus vom ${date}`,
    corpusHeadingNone: "Schwachstellen: nicht geprüft",
    corpusBody: (date: string) =>
      `Diese Apps wurden gegen einen Korpus vom ${date} geprüft. Alles, was seither veröffentlicht wurde, wurde nicht betrachtet; dieses Datum bewegt sich nur, wenn der Korpus aktualisiert wird.`,
    corpusBodyNone:
      "In diesem Container ist kein Schwachstellen-Korpus geladen; LoonInspect hat daher keine dieser Apps geprüft. Jede Zeile steht auf nicht geprüft und trägt kein Datum – weil es kein Korpus-Datum gibt.",
    edge: (date: string) =>
      `Was dieser Korpus nicht abdeckt, wird benannt statt verschwiegen: Eine App, die er nicht kennt, steht auf außerhalb des Korpus, datiert auf den ${date} – nie auf null Schwachstellen.`,
    edgeNone:
      "Was dieser Container nicht geprüft hat, wird benannt statt verschwiegen: Ohne geladenen Korpus steht jede App auf nicht geprüft und trägt kein Datum – nie null Schwachstellen.",
    stateCoveredClean: "Keine Funde",
    stateUnknownApp: "Außerhalb des Korpus",
    stateOff: "Nicht geprüft",
    stateOffReason: "kein Korpus geladen",
    checkedAgainstCorpusOf: (date: string) => `geprüft gegen den Korpus vom ${date}`,
    notInCorpusOf: (date: string) => `nicht im Korpus vom ${date}`,
    findings: (count: number) => `${count} Fund${count === 1 ? "" : "e"}`,
    kev: (count: number) => `${count} auf der CISA-KEV-Liste`,
    oldestPublished: (days: number) => `ältester Fund vor ${days} Tag${days === 1 ? "" : "en"} veröffentlicht`,
    moreIds: (count: number) => `+${count} weitere`,
    idsCapped: "Liste gekürzt"
  },
  jamfPatch: {
    tabLabel: "Jamf Patch",
    eyebrow: "Geräte › Anwendungen",
    title: "Jamf Patch",
    description: "Software-Titel aus dem Jamf-Patch-Katalog, stündlich synchronisiert.",
    tableName: "Name",
    tablePublisher: "Herausgeber",
    tableBundleId: "Bundle-ID",
    tableCurrentVersion: "Aktuelle Version",
    tableDeviceCount: "Geräte mit App",
    tableDevicesOnLatest: "Geräte auf neuester Version",
    tableLastModified: "Zuletzt geändert",
    tableSyncedAt: "Zuletzt synchronisiert",
    syncNow: "Jetzt synchronisieren",
    syncing: "Synchronisiert...",
    syncError: "Synchronisierung fehlgeschlagen. Bitte erneut versuchen.",
    searchPlaceholder: "Name, Herausgeber, Bundle-ID, Version suchen...",
    searchModeExact: "Exakt",
    searchModeRegex: "Regex",
    searchModeFuzzy: "Unscharf",
    loading: "Lädt...",
    errorLoading: "Jamf-Patch-Titel konnten nicht geladen werden.",
    empty: "Noch keine Jamf-Patch-Titel synchronisiert.",
    noMatches: "Keine Titel entsprechen dieser Suche.",
    total: (n: number) => `${n} Titel insgesamt`,
    filteredTotal: (shown: number, total: number) =>
      shown === total ? `${total} Titel insgesamt` : `${shown} von ${total} Titeln`,
    detail: {
      back: "← Zurück zu Jamf Patch",
      loading: "Lädt...",
      errorLoading: "Dieser Titel konnte nicht geladen werden.",
      notFound: "Titel nicht gefunden.",
      tableVersion: "Version",
      tableReleaseDate: "Veröffentlichungsdatum",
      empty: "Für diesen Titel ist keine Versionshistorie vorhanden.",
      versionsTitle: "Versionshistorie",
      versionsTotal: (n: number) => `${n} Version${n === 1 ? "" : "en"}`,
      tableDeviceCount: "Geräte mit Version",
      deviceSummary: (devices: number, onLatest: number) =>
        devices === 0
          ? "Kein Gerät dieses Mandanten hat eine App, die diesem Titel zugeordnet ist."
          : `${devices} Gerät${devices === 1 ? "" : "e"} mit diesem Titel · ${onLatest} auf der aktuellen Version`,
      unlistedVersions: (n: number) =>
        `${n} Gerät${n === 1 ? "" : "e"} auf einer Version, die Jamf nicht führt (dem Katalog voraus oder ein Build, den Jamf nie erfasst hat).`,
      tableVulnerabilities: "Schwachstellen",
      vulnerabilitiesTooltip: "Noch nicht bewertet — Schwachstellendaten kommen mit dem Community-Korpus (docs/vulnerabilities.md).",
      vulnCritical: "Kritisch",
      vulnHigh: "Hoch",
      vulnMedium: "Mittel",
      vulnLow: "Niedrig",
      vulnTotal: "Gesamt",
      calendarTitle: "Release-Rhythmus",
      calendarDescription:
        "Jedes Quadrat ist ein Tag, an dem eine Version dieses Titels veröffentlicht wurde — dunkler bedeutet mehr Releases an diesem Tag.",
      calendarMon: "Mo",
      calendarWed: "Mi",
      calendarFri: "Fr",
      calendarLess: "Weniger",
      calendarMore: "Mehr",
      calendarNoReleases: (date: string) => `Keine Releases am ${date}`,
      calendarReleases: (n: number, date: string) => `${n} Release${n === 1 ? "" : "s"} am ${date}`,
      calendarAriaLabel: (n: number) =>
        `Release-Kalender mit ${n} Release${n === 1 ? "" : "s"} in den letzten 12 Monaten. Die vollständige Liste finden Sie in der Versionshistorie-Tabelle unten.`,
      requirementsTitle: "Anforderungen",
      requirementsDescription:
        "Die Erkennungskriterien, die Jamf zur Identifikation dieses Titels verwendet. Gruppen sind ODER-verknüpft; Tests innerhalb einer Gruppe sind UND-verknüpft.",
      requirementsEmpty: "Für diesen Titel sind keine Anforderungen hinterlegt.",
      requirementsOr: "ODER",
      requirementsAnd: "UND",
      testTitle: "Anforderungen testen",
      testDescription:
        "Geben Sie Beispielwerte ein, um zu sehen, ob sie den Anforderungen dieses Titels entsprechen würden — nützlich, wenn eine Bundle-ID von mehreren Titeln geteilt wird (z. B. unterschiedliche Hauptversionen).",
      testAppName: "App-Name",
      testBundleId: "Bundle-ID",
      testShortVersion: "Kurzversion",
      testBundleVersion: "Bundle-Version",
      testEaName: "Name des Extension Attributes",
      testEaValue: "Wert des Extension Attributes",
      testVerdictMatched: "Übereinstimmung — diese Werte erfüllen mindestens eine Anforderungsgruppe",
      testVerdictNotMatched: "Keine Übereinstimmung — diese Werte erfüllen keine Anforderungsgruppe",
      testVerdictInconclusive: "Nicht eindeutig — zu wenige Testwerte, um eine Gruppe auszuwerten"
    }
  },
  smartGroupCost: {
    eyebrow: "Ger\u00e4te",
    title: "Kosten smarter Gruppen",
    description:
      "Ihre smarten Jamf-Gruppen, sortiert danach, wie viel Arbeit ihre Kriterien bei jeder Neuberechnung der Mitgliedschaft bedeuten.",
    advisoryTitle: "Ein Hinweis, keine Messung",
    advisoryBody:
      "Diese Rangfolge leitet sich aus den Kriterien ab, die Ihr Jamf Pro meldet, und zwar danach, was ein Operator mit dem Wert eines einzelnen Ger\u00e4ts tun muss \u2014 eine Regex-Auswertung ist aufwendiger als eine Teilstring-Suche, und die ist aufwendiger als ein einfacher Vergleich. LoonInspect misst Ihren Jamf-Server nicht; nichts hier ist ein Benchmark. Lesen Sie es als \u201ediese Gruppen zuerst ansehen\u201c, niemals als Zahl.",
    bandRegex: "Regex",
    bandRegexHelp: "Mindestens ein Kriterium l\u00e4sst eine Regex \u00fcber den Wert jedes Ger\u00e4ts laufen.",
    bandSubstring: "Teilstring",
    bandSubstringHelp: "Das schwerste Kriterium durchsucht den Wert jedes Ger\u00e4ts nach einem Fragment.",
    bandUnknown: "Unbekannt",
    bandUnknownHelp: "Ein Operator, den LoonInspect nicht kennt. Wird angezeigt statt geraten.",
    bandDependent: "Gruppenmitgliedschaft",
    bandDependentHelp: "Pr\u00fcft die Mitgliedschaft in einer anderen Gruppe und kostet daher, was jene Gruppe kostet.",
    bandExact: "Exakt",
    bandExactHelp: "Jedes Kriterium vergleicht zwei Werte genau einmal.",
    bandNone: "Keine Kriterien",
    bandNoneHelp: "Die beobachtete Definition enth\u00e4lt \u00fcberhaupt keine Kriterien.",
    tableRank: "#",
    tableName: "Gruppe",
    tableBand: "Schwerster Operator",
    tableCriteria: "Kriterien",
    tableDepth: "Verschachtelung",
    tableObserved: "Zuletzt beobachtet",
    unnamed: "Unbenannte Gruppe",
    unknownOperatorBadge: "unbekannter Operator",
    extensionAttributeBadge: "Erweiterungsattribut",
    criterionOrder: "Reihenfolge",
    criterionField: "Gepr\u00fcftes Feld",
    criterionOperator: "Jamf-Operator",
    criterionClass: "Klasse",
    criterionValue: "Wert",
    criterionDepth: (depth: number) => `Tiefe ${depth}`,
    noCriteria: "Die beobachtete Definition dieser Gruppe hat keine Kriterien.",
    loading: "Smarte Gruppen werden geladen\u2026",
    errorLoading: "Smarte Gruppen konnten nicht geladen werden.",
    empty: "Noch keine Definitionen smarter Gruppen beobachtet. Sie kommen mit der ersten Katalog-Sammlung.",
    total: (n: number) => `${n} smarte Gruppe${n === 1 ? "" : "n"} beobachtet`
  },
  settings: {
    eyebrow: "Einstellungen",
    title: "MDM-Verbindungen",
    addConnection: "Verbindung hinzufügen",
    tableName: "Name",
    tableProvider: "Anbieter",
    tableBaseUrl: "Basis-URL",
    tablePatchMgmt: "Patch-Verwaltung",
    tableStatus: "Status",
    tableLastSync: "Letzte Synchronisierung",
    syncNow: "Jetzt synchronisieren",
    syncRunning: "Wird synchronisiert…",
    syncFailed: "Letzte Synchronisierung fehlgeschlagen",
    syncNever: "Nie synchronisiert",
    syncDeviceCount: (n: number) => `${n} Gerät${n === 1 ? "" : "e"}`,
    syncError: "Die Synchronisierung konnte nicht gestartet werden.",
    runProcessing: "Wird verarbeitet…",
    runJoined: "Läuft bereits — der laufende Durchlauf wird angezeigt.",
    runMoreDetails: "Mehr Details",
    runHideDetails: "Details ausblenden",
    runLogEmpty: "Warten auf die erste Zeile…",
    runSucceeded: "Abgeschlossen",
    runFailed: "Fehlgeschlagen",
    runSummary: (devices: number, groups: number) =>
      `${devices} Gerät${devices === 1 ? "" : "e"}, ${groups} Gruppe${groups === 1 ? "" : "n"}`,
    runDevicesFailed: (n: number) => `${n} fehlgeschlagen`,
    runJobId: "Job-ID",
    loading: "Lädt...",
    empty: "Noch keine Verbindungen.",
    errorLoading: "Verbindungen konnten nicht geladen werden.",
    errorDeleting: "Die Verbindung konnte nicht gelöscht werden.",
    active: "Aktiv",
    inactive: "Inaktiv",
    deleteConfirm: (name: string) =>
      `"${name}" löschen? Die zugehörigen Geräte, deren Apps und deren Verlauf werden mitgelöscht.`,
    deleting: "Wird gelöscht...",
    confirm: "Bestätigen",
    cancel: "Abbrechen",
    edit: "Bearbeiten",
    delete: "Löschen"
  },
  collections: {
    heading: "Sammlungen",
    intro: "Was von dieser Verbindung eingesammelt wird, und wann. Die Verbindung hält die Zugangsdaten; jede Sammlung ist ein Abruf mit eigenem Umfang und Zeitplan.",
    add: "Sammlung hinzufügen",
    empty: "Noch keine Sammlungen – die Standardsammlungen entstehen beim Speichern einer Jamf-Pro-Verbindung.",
    loading: "Sammlungen werden geladen…",
    colName: "Name",
    colKind: "Art",
    colWhat: "Was",
    colWhen: "Wann",
    colLastRun: "Letzter Lauf",
    colNextDue: "Nächster Lauf",
    kinds: {
      device_sweep: "Geräte-Durchlauf",
      catalog: "Gruppenkatalog",
      webhook: "Webhook"
    } as Record<string, string>,
    sectionsCount: (n: number) => `${n} Abschnitt${n === 1 ? "" : "e"}`,
    allSections: "Alle Abschnitte",
    selectorLabel: "Filter",
    noSelector: "Alle Geräte",
    quarantineCount: (n: number) => `${n} EA${n === 1 ? "" : "s"} in Quarantäne`,
    catalogWhat: "Smart-Group-Definitionen mit Kriterien",
    webhookWhat: "Umfang des Abrufs, den ein Webhook auslöst",
    eventDriven: "Ereignisgesteuert",
    frequency: {
      hourly: "Stündlich",
      daily: "Täglich",
      weekly: "Wöchentlich",
      every_n_days: "Alle N Tage"
    } as Record<string, string>,
    scheduleHourly: (minute: string) => `Stündlich um :${minute}`,
    scheduleDaily: (time: string, zone: string) => `Täglich um ${time} ${zone}`,
    scheduleWeekly: (day: string, time: string, zone: string) => `Wöchentlich am ${day} um ${time} ${zone}`,
    scheduleEveryN: (n: number, time: string, zone: string) => `Alle ${n} Tage um ${time} ${zone}`,
    weekdays: ["Montag", "Dienstag", "Mittwoch", "Donnerstag", "Freitag", "Samstag", "Sonntag"],
    never: "Nie",
    runOk: "OK",
    runFailed: "Fehlgeschlagen",
    runSkipped: "Übersprungen",
    runSummary: (devices: number, groups: number) => `${devices} Gerät${devices === 1 ? "" : "e"}, ${groups} Gruppe${groups === 1 ? "" : "n"}`,
    disabled: "Deaktiviert",
    enable: "Aktivieren",
    disable: "Deaktivieren",
    runNow: "Jetzt ausführen",
    runQueued: "Eingereiht",
    runError: "Der Lauf konnte nicht gestartet werden.",
    edit: "Bearbeiten",
    delete: "Löschen",
    deleteConfirm: (name: string) => `Sammlung „${name}“ löschen?`,
    form: {
      createTitle: "Neue Sammlung",
      editTitle: "Sammlung bearbeiten",
      name: "Name",
      kind: "Art",
      kindHelp: "Ein Geräte-Durchlauf liest das Inventar und endet mit einer Gruppenaktualisierung; ein Katalog liest nur Smart-Group-Definitionen; eine Webhook-Sammlung hat keinen Zeitplan und bestimmt den Umfang des Abrufs, den ein Jamf-Webhook auslöst.",
      enabled: "Aktiviert",
      sections: "Abschnitte",
      sectionsHelp: "Nur diese Abschnitte werden von Jamf angefordert und gehasht. Eine Einschränkung wird als Aperturwechsel festgehalten, nicht als Verschwinden der ausgelassenen Abschnitte. Extension Attributes werden innerhalb des Abschnitts gemeldet, unter dem ein Admin sie anzeigt; wer sie anfordert, liest daher auch General, Hardware, Operating System, User and Location und Purchasing.",
      carriesExtensionAttributes: "trägt Extension Attributes",
      selectAll: "Alle auswählen",
      selectNone: "Keine auswählen",
      selector: "Gerätefilter (Jamf RSQL)",
      selectorHelp: "Wird in die Jamf-Abfrage geschoben, nicht ausgewählte Geräte kosten kein API-Budget. Leer lassen für alle Geräte.",
      selectorPresets: {
        all: "Alle Geräte",
        managed: "Nur verwaltete",
        unmanaged: "Nur unverwaltete"
      } as Record<string, string>,
      pageSize: "Seitengröße überschreiben",
      pageSizePlaceholder: "Von der Verbindung erben",
      pageSizeHelp: "Geräte pro Inventarseite, nur für diese Collection. Leer erbt die Einstellung der Verbindung; eine schmale Collection (wenige Sektionen) verträgt größere Seiten als der Worst Case der Verbindung.",
      quarantine: "Erweiterungsattribute in Quarantäne",
      quarantineHelp: "Definitions-IDs von Erweiterungsattributen, die sich bei jedem Recon ändern (Uptime, Akku, freier Speicher). Ihre Werte werden nicht gehasht und können das Ledger nicht aufwirbeln.",
      schedule: "Zeitplan",
      frequency: "Häufigkeit",
      time: "Uhrzeit",
      minute: "Minute",
      weekday: "Wochentag",
      intervalN: "Alle N Tage",
      timezone: "Zeitzone",
      timezoneHelp: "IANA-Name, z. B. Europe/Berlin. Die Uhrzeit bleibt über die Sommerzeit hinweg auf dieser Uhr.",
      save: "Speichern",
      saving: "Wird gespeichert…",
      cancel: "Abbrechen",
      error: "Die Sammlung konnte nicht gespeichert werden."
    }
  },
  changes: {
    title: "Änderungen",
    description:
      "Das Änderungsprotokoll jedes Geräts zwischen zwei Beobachtungszeiträumen. Enthalten ist, was Ihre Änderungsverfolgung als relevant eingestuft hat.",
    search: "Suche",
    searchPlaceholder: "Gerätename, Seriennummer oder Jamf-ID",
    artifact: "Auf ein Objekt filtern",
    artifactPlaceholder: "App-Name, Bundle-ID, Benutzername, Gruppe…",
    artifactHint: "App, Konto, Gruppe oder Profil – keine Pfade und nicht die Werte selbst.",
    filterTo: (name: string) => `Auf ${name} filtern`,
    clearFilter: "Filter entfernen",
    level: "Stufe",
    anyLevel: "Alle Stufen",
    section: "Abschnitt",
    anySection: "Alle Abschnitte",
    apply: "Anwenden",
    loading: "Änderungen werden geladen…",
    empty: "Noch keine Änderungen – sie erscheinen ab der zweiten Beobachtung eines Geräts.",
    errorLoading: "Änderungen konnten nicht geladen werden.",
    colWhen: "Beobachtet",
    colDevice: "Gerät",
    colWhat: "Was",
    colChange: "Änderung",
    colWhatChanged: "Was sich geändert hat",
    levels: { high: "Hoch", normal: "Normal", low: "Niedrig" } as Record<string, string>,
    changeKinds: { changed: "Geändert", added: "Hinzugefügt", removed: "Entfernt", updated: "Aktualisiert" } as Record<string, string>,
    entryKinds: {
      application: "Anwendung",
      extension_attribute: "Erweiterungsattribut",
      group_membership: "Smart Group",
      configuration_profile: "Profil",
      local_user_account: "Lokales Konto",
      certificate: "Zertifikat",
      software_update: "Ausstehendes Update"
    } as Record<string, string>,
    sections: {
      general: "Allgemein",
      hardware: "Hardware",
      operating_system: "Betriebssystem",
      user_and_location: "Benutzer und Standort",
      purchasing: "Beschaffung",
      security: "Sicherheit",
      disk_encryption: "Festplattenverschlüsselung",
      definition: "Smart-Group-Definition",
      applications: "Anwendungen",
      extension_attributes: "Erweiterungsattribute",
      group_memberships: "Smart-Group-Mitgliedschaften",
      configuration_profiles: "Konfigurationsprofile",
      local_user_accounts: "Lokale Konten",
      certificates: "Zertifikate",
      software_updates: "Ausstehende Updates"
    } as Record<string, string>,
    systemAppsUpdated: (n: number) => `${n} Apple-System-App${n === 1 ? "" : "s"} mit dem OS aktualisiert`,
    criteriaMoved: "Kriterien geändert",
    deviceDrifted: "Gerät hat sich verändert",
    count: (n: number) => `${n} Änderung${n === 1 ? "" : "en"}`,
    pageOf: (page: number, pages: number) => `Seite ${page} von ${pages}`,
    previous: "Zurück",
    next: "Weiter"
  },
  changeTracking: {
    title: "Änderungsverfolgung",
    description: "Jedes Feld, das das Ledger beobachtet, trägt eine Stufe – hoch (Sicherheitslage, privilegierte Konten, Verwaltungsstatus, Hardware-Identität), normal (Inventar) oder niedrig (Kosmetik, Asset-Metadaten, flottenweites Rauschen). Die Stufe setzt den Standard; schalten Sie um, was Sie möchten. Nur Ihre Änderungen werden gespeichert, unberührte Zeilen folgen künftigen Standards. Die Historie bleibt unabhängig davon erhalten – später Eingeschaltetes lässt sich nachspielen.",
    loading: "Richtlinie wird geladen…",
    errorLoading: "Die Richtlinie konnte nicht geladen werden.",
    errorSaving: "Die Richtlinie konnte nicht gespeichert werden.",
    saved: "Gespeichert.",
    presetTitle: "Voreinstellung",
    presetHelp: "Welche Stufen eingeschaltet sind, sofern Sie nichts anderes festlegen.",
    presets: { high: "Nur hoch", normal: "Hoch + normal (Standard)", low: "Alles" } as Record<string, string>,
    systemApps: "Apple-System-Apps (/System) einzeln protokollieren",
    systemAppsHelp: "Standardmäßig aus: ein macOS-Update hebt rund sechzig System-Apps auf einmal an, daher werden sie als Zahl im OS-Update zusammengefasst.",
    showLow: "Felder der Stufe niedrig anzeigen",
    entriesTitle: "Listen – Anwendungen, Konten, Gruppen, Profile, Zertifikate",
    added: "hinzugefügt",
    removed: "entfernt",
    fieldsTitle: "Felder",
    sections: {
      general: "Allgemein",
      hardware: "Hardware",
      operating_system: "Betriebssystem",
      user_and_location: "Benutzer und Standort",
      purchasing: "Beschaffung",
      security: "Sicherheit",
      disk_encryption: "Festplattenverschlüsselung",
      definition: "Smart-Group-Definitionen"
    } as Record<string, string>,
    levels: { high: "hoch", normal: "normal", low: "niedrig" } as Record<string, string>,
    mutedGroups: "Stummgeschaltete Smart Groups",
    mutedGroupsHelp: "Beitritt und Austritt bei diesen Gruppen werden nicht protokolliert – für Gruppen, die absichtlich fluktuieren.",
    mutedEas: "Stummgeschaltete Erweiterungsattribute",
    mutedEasHelp: "Wertänderungen dieser Attribute werden nicht protokolliert. Die Quarantäne (in der Sammlung) geht weiter und hält sie ganz aus dem Ledger heraus.",
    noneKnown: "Noch keine beobachtet.",
    save: "Speichern",
    saving: "Wird gespeichert…",
    reset: "Auf Standard zurücksetzen",
    overrideCount: (n: number) => `${n} Abweichung${n === 1 ? "" : "en"}`
  },
  ai: {
    title: "KI",
    description:
      "Ein Testfeld: ein Prompt an einen Modell-Endpunkt Ihrer Wahl, hinter dem KI-Flag und der Einwilligung zur KI-Inferenz. Nichts wird gespeichert. Jedes Senden schreibt eine Zeile ins Freigabeprotokoll mit dem Ziel und dem einen Feld, das den Pod verlassen hat: dem Prompt. Der Aufruf geht von diesem Server aus, nie von Ihrem Browser.",
    on: "An",
    off: "Aus",
    flagLabel: "KI-Funktionen-Flag",
    flagHelp: "Unter Feature-Flags ändern",
    consentLabel: "Einwilligung zur KI-Inferenz",
    consentOn: "Erteilt",
    consentOff: "Nicht erteilt",
    consentToggleOn: "Einwilligung erteilen",
    consentToggleOff: "Einwilligung widerrufen",
    consentHelp: "Ob überhaupt ein Byte diesen Pod zur Inferenz verlassen darf. Dieselbe Einwilligungsschiene wie die Community-Datenfreigabe.",
    detectionHeading: "Wo dieser Container läuft",
    detectionDockerDesktopMac: "Docker Desktop unter macOS erkannt. Die Karte Apple Foundation Models passt zu dieser Umgebung.",
    detectionDockerDesktop: "Docker Desktop erkannt; das Host-Betriebssystem ließ sich aus dem Container nicht erkennen.",
    detectionUnknown: "Laufzeitumgebung aus dem Container nicht erkannt. Wählen Sie selbst eine Karte.",
    detectionEvidence: "Belege",
    providersHeading: "Endpunkt",
    providerLabels: {
      apple_fm: "Apple Foundation Models über Docker Desktop",
      openai_compatible: "OpenAI-kompatibel",
      anthropic: "Anthropic"
    },
    providerHelp: {
      apple_fm:
        "Hier klicken, wenn LoonInspect unter Docker Desktop auf diesem Mac läuft und ein OpenAI-kompatibler Shim Apples On-Device-Modell bereitstellt.",
      openai_compatible:
        "Standardmäßig Ollama auf diesem Mac. Ebenso OpenAI selbst, ein Gateway, LM Studio oder vLLM. Eigene URL und eigener Schlüssel.",
      anthropic: "Die Messages-API. Eigener Schlüssel."
    },
    otherRuntimes: "OrbStack, Colima oder Podman im Einsatz? Noch nicht unterstützt. Geben Sie stattdessen die URL ein.",
    baseUrl: "Basis-URL",
    model: "Modell",
    apiKey: "API-Schlüssel",
    apiKeyOptional: "optional",
    apiKeyRequired: "erforderlich",
    reasoningEffort: "Denkaufwand",
    reasoningDefault: "Standard des Endpunkts",
    prompt: "Prompt",
    promptDefault: "Erzähl mir einen Witz.",
    send: "Senden",
    sending: "Sendet…",
    sendBlocked: "Senden setzt das Flag, die Einwilligung, system:write und ausgefüllte Felder voraus.",
    sendFailed: "Die Anfrage konnte nicht gesendet werden.",
    resultHeading: "Antwort",
    outcome: {
      answered: "Beantwortet",
      empty: "Leere Antwort",
      budget_exhausted_thinking: "Budget beim Nachdenken aufgebraucht",
      error: "Fehlgeschlagen"
    },
    budgetExhaustedHelp:
      "Das Modell hat sein gesamtes Token-Budget mit Nachdenken verbraucht und nie geantwortet. Denkaufwand auf none setzen oder das Budget erhöhen.",
    reasoning: "Gedankengang (eingeklappt)",
    destination: "Ziel",
    latency: "Latenz",
    tokens: "Antwort-Token",
    finish: "Abbruchgrund",
    loadFailed: "Die KI-Seite konnte nicht geladen werden.",
    saveFailed: "Die Einwilligung konnte nicht geändert werden."
  },
  featureFlags: {
    title: "Feature-Flags",
    description:
      "Erzwingen Sie Funktionen, die normalerweise hinter Verbindungsfähigkeiten oder anderen Bedingungen verborgen sind.",
    loading: "Lädt...",
    empty: "Noch keine Feature-Flags definiert.",
    errorLoading: "Feature-Flags konnten nicht geladen werden.",
    errorUpdating: "Dieses Flag konnte nicht aktualisiert werden. Bitte erneut versuchen.",
    on: "An",
    off: "Aus"
  },
  connectionForm: {
    name: "Name",
    provider: "Anbieter",
    baseUrl: "Basis-URL",
    baseUrlPlaceholder: "https://ihre-org.jamfcloud.com",
    credentials: "Anmeldedaten",
    pasteJson: "Stattdessen JSON einfügen",
    enterManually: "Felder manuell eingeben",
    jsonPlaceholder: '{"client_id": "...", "client_secret": "...", ...}',
    jsonParsedHint: "Felder aus JSON übernommen.",
    loadingFields: "Felder für diesen Anbieter werden geladen...",
    setLeaveBlank: "(gesetzt — leer lassen, um beizubehalten)",
    showPrivileges: "Welche Jamf-Pro-Berechtigungen werden benötigt?",
    hidePrivileges: "Berechtigungen ausblenden",
    privilegesIntro:
      "Die diesem API-Client zugewiesene API-Rolle braucht diese Leseberechtigungen. Alle fünf sind Lesezugriffe; keine schreibt etwas nach Jamf Pro.",
    privilegesExactNames:
      "Genau so eingeben, wie hier geschrieben — das sind Jamfs eigene Bezeichnungen, und der Editor für API-Rollen sucht danach.",
    testProvesOnlyAuth:
      "„Verbindung testen“ tauscht diese Zugangsdaten nur gegen ein Token — der einzige Jamf-Pro-Aufruf, der keine Berechtigung braucht. Die API-Rolle wird dabei nicht geprüft: Eine Rolle ohne jede Berechtigung besteht den Test und synchronisiert danach kein einziges Gerät.",
    testConnection: "Verbindung testen",
    testing: "Wird getestet...",
    testRequestFailed: "Testanfrage fehlgeschlagen.",
    viewRawResponse: "Die Rohantwort von Jamf anzeigen",
    patchManagement: "Patch-Verwaltung",
    patchProviderLabels: { none: "Keine", jamf: "Jamf", loonsecio: "LoonSecIO" },
    loonsecioComingSoon: "(demnächst)",
    advancedSettings: "Erweiterte Einstellungen",
    hideAdvancedSettings: "Erweiterte Einstellungen ausblenden",
    userAgentOverride: "User-Agent-Override",
    userAgentPlaceholder: "LoonSecIO (Standard)",
    userAgentHint:
      'Wird als Produktname im User-Agent-Header bei jeder Anfrage an Jamf Pro gesendet (z. B. "LoonSecIO/0.1.0 auth"). Leer lassen, um den Instanzstandard zu verwenden.',
    sweepPageSize: "Seitengröße des Sweeps",
    sweepPageSizeDefault: "(Standard)",
    sweepPageSizeHint:
      "Geräte pro Inventarseite, ausgelegt auf einen Sweep mit allen Sektionen. Der begrenzende Faktor sind die Sektionen, nicht die API: je mehr Sektionen die Collections pro Gerät abrufen, desto kleiner sollten die Seiten sein.",
    whatUsedFor: "Wofür diese Verbindung verwendet wird",
    capabilityDevices: "Geräte",
    capabilityUsers: "Benutzer",
    capabilityWebhooks: "Callback-Webhooks",
    capabilityJamfPro: "Jamf Pro",
    crud: "(CRUD)",
    readOnly: "(lesend)",
    webhookSecret: "Webhook-Geheimnis",
    webhookSecretHint:
      "Wird mit Jamf Pro geteilt: denselben Wert dort am Webhook hinterlegen, als Wert der Header-Authentifizierung (Header-Name X-API-Key) oder als Passwort der Basic-Authentifizierung. Wird verschlüsselt gespeichert und nie wieder angezeigt — zum Ändern hier einen neuen Wert eingeben und Jamf Pro entsprechend anpassen.",
    webhookSecretRequired:
      "Callback-Webhooks benötigen ein Geheimnis. Ohne dieses weist der Webhook-Endpunkt jede Anfrage von Jamf Pro zurück.",
    baseUrlChangeNeedsSecret: (fields: string) =>
      `Beim Ändern der URL müssen ${fields} erneut eingegeben werden. Die gespeicherten Anmeldedaten werden nur an die URL gesendet, unter der sie gespeichert wurden.`,
    lastSuccessfulAuth: "Letzte erfolgreiche Authentifizierung:",
    never: "Nie",
    credentialsRotated: "Anmeldedaten zuletzt rotiert:",
    startsWithFingerprint: (fp: string) => `(beginnt mit "${fp}")`,
    saveChanges: "Änderungen speichern",
    addConnectionButton: "Verbindung hinzufügen",
    cancel: "Abbrechen",
    saveError: "Verbindung konnte nicht gespeichert werden. Werte prüfen und erneut versuchen.",
    jsonNoMatch: (fields: string) => `Keines der Felder dieses Anbieters (${fields}) wurde in diesem JSON gefunden.`,
    jsonParseError: "JSON konnte nicht geparst werden — Format prüfen."
  }
};
