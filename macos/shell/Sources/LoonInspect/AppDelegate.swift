import AppKit
import WebKit

/// The window: one WKWebView on the backend's own UI, native startup and recovery views,
/// a readable failure with direct access to logs, and the app menu's
/// Open in Browser, Show Logs in Finder and Quit. On a first launch the window's page is handed
/// this session's setup claim token. Quitting (the menu, ⌘Q, `osascript -e 'quit app
/// "LoonInspect"'`, logout, SIGTERM) stops the children first.
@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate, NSMenuItemValidation, WKNavigationDelegate, WKUIDelegate, WKDownloadDelegate {
    private let supervisor: Supervisor
    private var window: NSWindow!
    private var webView: WKWebView!
    private var statusView: StatusView!
    private lazy var guide = MacGuideWindow()
    private var port: Int?
    private var lastLocalURL: URL?
    private var activity: NSObjectProtocol?
    private var quitting = false
    private var serviceFailed = false
    private var stoppingServices = false
    private var servicesStopped = false
    private var afterStop: [() -> Void] = []
    private var downloads: [ObjectIdentifier: ExportDestination] = [:]
    private var reportedFirstPage = false
    private var signalSources: [DispatchSourceSignal] = []

    init(supervisor: Supervisor) {
        self.supervisor = supervisor
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        buildMenu()
        buildWindow()
        show("Starting LoonInspect", "Preparing your local workspace on this Mac.", spinner: true)
        for sig in [SIGTERM, SIGINT, SIGHUP] {
            signal(sig, SIG_IGN)
            let source = DispatchSource.makeSignalSource(signal: sig, queue: .main)
            source.setEventHandler {
                // Not terminate() here: it waits for its reply in a nested run loop, and inside this
                // main-queue block the main queue (where the reply arrives) would never run again.
                CFRunLoopPerformBlock(CFRunLoopGetMain(), CFRunLoopMode.commonModes.rawValue) {
                    MainActor.assumeIsolated { NSApp.terminate(nil) }
                }
                CFRunLoopWakeUp(CFRunLoopGetMain())
            }
            source.resume()
            signalSources.append(source)
        }
        let supervisor = self.supervisor
        supervisor.onProgress = { title, message in
            Task { @MainActor in
                guard !self.quitting, !self.serviceFailed, self.port == nil else { return }
                self.show(title, message, spinner: true)
            }
        }
        supervisor.onUnexpectedExit = { message in Task { @MainActor in self.failService(message) } }
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let port = try supervisor.start()
                Task { @MainActor in self.started(port: port) }
            } catch {
                guard !supervisor.isStopping else { return }
                supervisor.log.error("\(error)")
                Task { @MainActor in self.failService("\(error)") }
            }
        }
    }

    func applicationSupportsSecureRestorableState(_ app: NSApplication) -> Bool { true }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        if !flag { window.makeKeyAndOrderFront(nil) }
        return true
    }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard !quitting else { return .terminateLater }
        quitting = true
        show("Stopping LoonInspect…", "Stopping the server, then the database.", spinner: true)
        stopServices { NSApp.reply(toApplicationShouldTerminate: true) }
        return .terminateLater
    }

    private func started(port: Int) {
        guard !quitting, !serviceFailed else { return }
        self.port = port
        // Keeps App Nap from throttling the scheduler while the window is hidden; sleep still wins.
        activity = ProcessInfo.processInfo.beginActivity(options: .userInitiatedAllowingIdleSystemSleep,
                                                         reason: "The LoonInspect server is running")
        handClaimTokenToWindow(port: port)
        reload()
    }

    /// The setup claim token, to this window's page and nowhere else. A container-era control, held
    /// by the shell for now and to be gutted before public release (Kyle, 2026-10-06;
    /// docs/macos-app.md). WebKit runs the script at document start, in the main frame only,
    /// and it defines a read-only `window.looninspectSetupClaimToken` only on this backend's origin;
    /// the setup page then draws no claim field. The shell puts the token in no URL, file, pasteboard
    /// or log line, and a browser opened with Open in Browser gets none: its setup page asks for it.
    private func handClaimTokenToWindow(port: Int) {
        guard let token = supervisor.claimToken(),
              token.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-" || $0 == "_") }) else {
            supervisor.log.info("no usable setup claim token in this session's backend log; none handed to the window")
            return
        }
        let source = """
            if (location.origin === "http://127.0.0.1:\(port)") {
              Object.defineProperty(window, "looninspectSetupClaimToken", { value: "\(token)" });
            }
            """
        webView.configuration.userContentController.addUserScript(
            WKUserScript(source: source, injectionTime: .atDocumentStart, forMainFrameOnly: true))
        supervisor.log.info("setup claim token from this session's backend log handed to the window")
    }

    private func failService(_ message: String) {
        guard !quitting, !serviceFailed else { return }
        let title = port == nil ? "LoonInspect could not start" : "The local service stopped"
        serviceFailed = true
        port = nil
        webView.stopLoading()
        if let activity { ProcessInfo.processInfo.endActivity(activity); self.activity = nil }
        show(title, message + "\n\nOpen the logs for details. After resolving the problem, quit and reopen LoonInspect.", spinner: false)
        stopServices {}
    }

    /// Startup failure and Quit can arrive together; run cleanup once and answer both callers.
    private func stopServices(_ completion: @escaping () -> Void) {
        afterStop.append(completion)
        if servicesStopped {
            DispatchQueue.main.async { self.finishStopping() }
            return
        }
        guard !stoppingServices else { return }
        stoppingServices = true
        let supervisor = self.supervisor
        DispatchQueue.global(qos: .userInitiated).async {
            supervisor.stop()
            Task { @MainActor in
                self.servicesStopped = true
                self.finishStopping()
            }
        }
    }

    private func finishStopping() {
        let completions = afterStop
        afterStop.removeAll()
        completions.forEach { $0() }
    }

    // MARK: - window and menu

    private func buildWindow() {
        let configuration = WKWebViewConfiguration()
        configuration.websiteDataStore = .default()
        webView = WKWebView(frame: .zero, configuration: configuration)
        webView.navigationDelegate = self
        webView.uiDelegate = self
        let visible = NSScreen.main?.visibleFrame ?? NSRect(x: 0, y: 0, width: 1440, height: 900)
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: min(1280, visible.width - 48), height: min(860, visible.height - 72)),
                          styleMask: [.titled, .closable, .miniaturizable, .resizable], backing: .buffered, defer: false)
        window.title = "LoonInspect"
        window.contentMinSize = NSSize(width: min(760, visible.width - 48), height: min(560, visible.height - 72))
        let content = NSView()
        statusView = StatusView(frame: .zero)
        statusView.onReload = { [weak self] in self?.reload() }
        statusView.onShowLogs = { [weak self] in self?.showLogs() }
        statusView.onQuit = { NSApp.terminate(nil) }
        for view in [webView!, statusView!] as [NSView] {
            view.translatesAutoresizingMaskIntoConstraints = false
            content.addSubview(view)
            NSLayoutConstraint.activate([
                view.leadingAnchor.constraint(equalTo: content.leadingAnchor),
                view.trailingAnchor.constraint(equalTo: content.trailingAnchor),
                view.topAnchor.constraint(equalTo: content.topAnchor),
                view.bottomAnchor.constraint(equalTo: content.bottomAnchor),
            ])
        }
        window.contentView = content
        window.isReleasedWhenClosed = false
        window.center()
        window.setFrameAutosaveName("LoonInspectMain")
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    private func buildMenu() {
        let main = NSMenu()
        func submenu(_ title: String, _ items: [NSMenuItem]) -> NSMenu {
            let menu = NSMenu(title: title)
            items.forEach(menu.addItem)
            let holder = NSMenuItem()
            holder.submenu = menu
            main.addItem(holder)
            return menu
        }
        func item(_ title: String, _ action: Selector, _ key: String = "", _ mask: NSEvent.ModifierFlags = .command) -> NSMenuItem {
            let item = NSMenuItem(title: title, action: action, keyEquivalent: key)
            item.keyEquivalentModifierMask = mask
            return item
        }
        _ = submenu("LoonInspect", [
            item("About LoonInspect", #selector(NSApplication.orderFrontStandardAboutPanel(_:))),
            .separator(),
            item("Open in Browser", #selector(openInBrowser), "b"),
            item("Show Logs in Finder", #selector(showLogs)),
            .separator(),
            item("Hide LoonInspect", #selector(NSApplication.hide(_:)), "h"),
            item("Quit LoonInspect", #selector(NSApplication.terminate(_:)), "q"),
        ])
        // Without an Edit menu, ⌘C, ⌘V and ⌘A do nothing in the page's fields.
        _ = submenu("Edit", [
            item("Undo", Selector(("undo:")), "z"),
            item("Redo", Selector(("redo:")), "z", [.command, .shift]),
            .separator(),
            item("Cut", #selector(NSText.cut(_:)), "x"),
            item("Copy", #selector(NSText.copy(_:)), "c"),
            item("Paste", #selector(NSText.paste(_:)), "v"),
            item("Select All", #selector(NSText.selectAll(_:)), "a"),
        ])
        _ = submenu("View", [item("Reload Window", #selector(reload), "r"),
            item("Enter Full Screen", #selector(NSWindow.toggleFullScreen(_:)), "f", [.command, .control])])
        NSApp.windowsMenu = submenu("Window", [
            item("Minimize", #selector(NSWindow.performMiniaturize(_:)), "m"),
            item("Zoom", #selector(NSWindow.performZoom(_:))),
            item("Close", #selector(NSWindow.performClose(_:)), "w"),
            item("Show LoonInspect", #selector(showWindow), "1"),
            .separator(),
            item("Bring All to Front", #selector(NSApplication.arrangeInFront(_:))),
        ])
        NSApp.helpMenu = submenu("Help", [
            item("Using LoonInspect on This Mac", #selector(showGuide)),
            item("Show Local Data in Finder", #selector(showData)),
        ])
        NSApp.mainMenu = main
    }

    func validateMenuItem(_ menuItem: NSMenuItem) -> Bool {
        switch menuItem.action {
        case #selector(openInBrowser), #selector(reload): return port != nil && !quitting
        default: return true
        }
    }

    @objc private func openInBrowser() {
        if let port { NSWorkspace.shared.open(URL(string: "http://127.0.0.1:\(port)/")!) }
    }

    @objc private func showLogs() { NSWorkspace.shared.open(supervisor.logDir) }
    @objc private func showData() { NSWorkspace.shared.open(supervisor.support) }
    @objc private func showGuide() { guide.show() }
    @objc private func reload() {
        guard let port, !quitting, !serviceFailed else { return }
        let url = lastLocalURL ?? URL(string: "http://127.0.0.1:\(port)/")!
        show("Opening your workspace", "Connecting to LoonInspect on this Mac.", spinner: true)
        webView.load(URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData))
    }
    @objc private func showWindow() { window.makeKeyAndOrderFront(nil); NSApp.activate(ignoringOtherApps: true) }

    private func show(_ title: String, _ body: String, spinner: Bool, canReload: Bool = false) {
        webView.isHidden = true
        statusView.isHidden = false
        statusView.update(title: title, message: body, busy: spinner, canReload: canReload)
    }

    // MARK: - web view

    private func isOurs(_ url: URL) -> Bool {
        url.scheme == "http" && url.host == "127.0.0.1" && url.port == port && port != nil
    }

    func webView(_ webView: WKWebView, decidePolicyFor action: WKNavigationAction,
                 decisionHandler: @escaping @MainActor (WKNavigationActionPolicy) -> Void) {
        if action.shouldPerformDownload { return decisionHandler(.download) }
        if let url = action.request.url, isOurs(url), action.targetFrame?.isMainFrame == true { lastLocalURL = url }
        guard let url = action.request.url, !isOurs(url), !["about", "blob", "data"].contains(url.scheme ?? "") else {
            return decisionHandler(.allow)
        }
        // Anything off this instance (documentation, GitHub, a Jamf console) opens in the browser.
        NSWorkspace.shared.open(url)
        decisionHandler(.cancel)
    }

    func webView(_ webView: WKWebView, decidePolicyFor response: WKNavigationResponse,
                 decisionHandler: @escaping @MainActor (WKNavigationResponsePolicy) -> Void) {
        let disposition = (response.response as? HTTPURLResponse)?.value(forHTTPHeaderField: "Content-Disposition") ?? ""
        decisionHandler(disposition.lowercased().hasPrefix("attachment") || !response.canShowMIMEType ? .download : .allow)
    }

    func webView(_ webView: WKWebView, navigationAction: WKNavigationAction, didBecome download: WKDownload) {
        download.delegate = self
    }

    func webView(_ webView: WKWebView, navigationResponse: WKNavigationResponse, didBecome download: WKDownload) {
        download.delegate = self
    }

    func download(_ download: WKDownload, decideDestinationUsing response: URLResponse, suggestedFilename: String,
                  completionHandler: @escaping @MainActor (URL?) -> Void) {
        guard !quitting else { completionHandler(nil); return }
        let panel = NSSavePanel()
        panel.title = "Save LoonInspect Export"
        panel.nameFieldStringValue = ExportDestination.suggestedName(suggestedFilename)
        panel.directoryURL = FileManager.default.urls(for: .downloadsDirectory, in: .userDomainMask).first
        panel.canCreateDirectories = true
        panel.beginSheetModal(for: window) { [weak self] response in
            guard let self, !self.quitting, response == .OK, let url = panel.url else {
                completionHandler(nil)
                return
            }
            let destination = ExportDestination(url: url)
            self.downloads[ObjectIdentifier(download)] = destination
            completionHandler(destination.stagingURL)
        }
    }

    func downloadDidFinish(_ download: WKDownload) {
        guard let destination = downloads.removeValue(forKey: ObjectIdentifier(download)) else { return }
        do {
            try destination.commit()
            supervisor.log.info("export saved to \(destination.url.path)")
            guard !quitting else { return }
            let alert = NSAlert()
            alert.messageText = "Export saved"
            alert.informativeText = destination.url.lastPathComponent
            alert.addButton(withTitle: "Show in Finder")
            alert.addButton(withTitle: "Done")
            alert.beginSheetModal(for: window) { response in
                if response == .alertFirstButtonReturn { NSWorkspace.shared.activateFileViewerSelecting([destination.url]) }
            }
        } catch {
            // Keep the completed staging file if a destination changed or became unavailable.
            reportExportFailure("The download completed, but could not be saved to the chosen location: \(error.localizedDescription). "
                + "The completed file is at \(destination.stagingURL.path).")
        }
    }

    func download(_ download: WKDownload, didFailWithError error: Error, resumeData: Data?) {
        downloads.removeValue(forKey: ObjectIdentifier(download))?.discard()
        guard (error as NSError).code != NSURLErrorCancelled else { return }
        reportExportFailure("\(error.localizedDescription)\n\nRetry the export. If it fails again, use LoonInspect → Open in Browser.")
    }

    private func reportExportFailure(_ message: String) {
        supervisor.log.error("export failed: \(message)")
        guard !quitting else { return }
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = "The export could not be saved"
        alert.informativeText = message
        alert.addButton(withTitle: "OK")
        alert.beginSheetModal(for: window)
    }

    func webView(_ webView: WKWebView, createWebViewWith configuration: WKWebViewConfiguration,
                 for action: WKNavigationAction, windowFeatures: WKWindowFeatures) -> WKWebView? {
        if let url = action.request.url {
            if isOurs(url) { webView.load(action.request) } else { NSWorkspace.shared.open(url) }
        }
        return nil
    }

    func webViewWebContentProcessDidTerminate(_ webView: WKWebView) {
        supervisor.log.error("the web view's content process ended; reloading")
        reload()
    }

    func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
        reportNavigationFailure(error)
    }

    func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
        reportNavigationFailure(error)
    }

    private func reportNavigationFailure(_ error: Error) {
        let failure = error as NSError
        guard !quitting, !serviceFailed, port != nil,
              !(failure.domain == NSURLErrorDomain && failure.code == NSURLErrorCancelled),
              let url = failure.userInfo[NSURLErrorFailingURLErrorKey] as? URL, isOurs(url) else { return }
        supervisor.log.error("window could not load local page: \(error.localizedDescription)")
        show("The window could not load", "The local service is running, but its page could not be displayed. "
            + "Try Reload Window, or open LoonInspect in your browser.\n\n\(error.localizedDescription)", spinner: false, canReload: true)
    }

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        guard !quitting, !serviceFailed, let url = webView.url, isOurs(url) else { return }
        webView.isHidden = false
        statusView.isHidden = true
        guard !reportedFirstPage else { return }
        reportedFirstPage = true
        // What the window shows, in the log: proof for a --headless-less test that the SPA rendered.
        DispatchQueue.main.asyncAfter(deadline: .now() + 2) { [self] in
            let probe = "JSON.stringify({title: document.title, path: location.pathname, "
                + "passwordField: !!document.querySelector('input[type=password]'), "
                + "claimField: !!document.getElementById('claimToken'), "
                + "tokenHanded: typeof window.looninspectSetupClaimToken === 'string'})"
            webView.evaluateJavaScript(probe) { result, error in
                self.supervisor.log.info("window shows \(result.map { "\($0)" } ?? "nothing: \(String(describing: error))")")
            }
        }
    }
}
