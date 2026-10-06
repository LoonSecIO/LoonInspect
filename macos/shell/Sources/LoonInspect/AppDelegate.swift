import AppKit
import WebKit

/// The window: one WKWebView on the backend's own UI, a waiting page while the supervisor
/// starts, a readable failure page with the log folder when it cannot, and the app menu's
/// Open in Browser, Show Logs in Finder and Quit. On a first launch the window's page is handed
/// this session's setup claim token. Quitting (the menu, ⌘Q, `osascript -e 'quit app
/// "LoonInspect"'`, logout, SIGTERM) stops the children first.
@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate, NSMenuItemValidation, WKNavigationDelegate, WKUIDelegate, WKDownloadDelegate {
    private let supervisor: Supervisor
    private var window: NSWindow!
    private var webView: WKWebView!
    private var port: Int?
    private var activity: NSObjectProtocol?
    private var quitting = false
    private var reportedFirstPage = false
    private var signalSources: [DispatchSourceSignal] = []

    init(supervisor: Supervisor) {
        self.supervisor = supervisor
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        buildMenu()
        buildWindow()
        show("Starting LoonInspect…", "The first launch creates the database and runs every migration, which takes longer "
            + "than the launches after it.", spinner: true)
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
        supervisor.onUnexpectedExit = { message in Task { @MainActor in self.fail(message) } }
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let port = try supervisor.start()
                Task { @MainActor in self.started(port: port) }
            } catch {
                guard !supervisor.isStopping else { return }
                supervisor.log.error("\(error)")
                Task { @MainActor in self.fail("\(error)") }
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
        let supervisor = self.supervisor
        DispatchQueue.global(qos: .userInitiated).async {
            supervisor.stop()
            Task { @MainActor in NSApp.reply(toApplicationShouldTerminate: true) }
        }
        return .terminateLater
    }

    private func started(port: Int) {
        guard !quitting else { return }
        self.port = port
        // Keeps App Nap from throttling the scheduler while the window is hidden; sleep still wins.
        activity = ProcessInfo.processInfo.beginActivity(options: .userInitiatedAllowingIdleSystemSleep,
                                                         reason: "The LoonInspect server is running")
        handClaimTokenToWindow(port: port)
        webView.load(URLRequest(url: URL(string: "http://127.0.0.1:\(port)/")!))
    }

    /// The setup claim token, to this window's page and nowhere else. A container-era control, held
    /// by the shell for now and to be gutted before public release (Kyle, 2026-10-06;
    /// docs/spike-macos-app.md). WebKit runs the script at document start, in the main frame only,
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

    private func fail(_ message: String) {
        guard !quitting else { return }
        show("LoonInspect could not start", message + "\n\nLogs: \(supervisor.logDir.path)\n(LoonInspect menu › Show Logs in Finder)",
             spinner: false)
    }

    // MARK: - window and menu

    private func buildWindow() {
        let configuration = WKWebViewConfiguration()
        configuration.websiteDataStore = .default()
        webView = WKWebView(frame: .zero, configuration: configuration)
        webView.navigationDelegate = self
        webView.uiDelegate = self
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1280, height: 860),
                          styleMask: [.titled, .closable, .miniaturizable, .resizable], backing: .buffered, defer: false)
        window.title = "LoonInspect"
        window.contentView = webView
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
        _ = submenu("View", [item("Reload", #selector(reload), "r")])
        NSApp.windowsMenu = submenu("Window", [
            item("Minimize", #selector(NSWindow.performMiniaturize(_:)), "m"),
            item("Close", #selector(NSWindow.performClose(_:)), "w"),
            item("Show LoonInspect", #selector(showWindow), "1"),
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
    @objc private func reload() { webView.reload() }
    @objc private func showWindow() { window.makeKeyAndOrderFront(nil) }

    private func show(_ title: String, _ body: String, spinner: Bool) {
        func escape(_ text: String) -> String {
            text.replacingOccurrences(of: "&", with: "&amp;").replacingOccurrences(of: "<", with: "&lt;").replacingOccurrences(of: ">", with: "&gt;")
        }
        let html = """
        <!doctype html><meta charset="utf-8"><title>LoonInspect</title>
        <style>
        :root { color-scheme: light dark; font: 14px -apple-system, system-ui, sans-serif; }
        body { margin: 0; min-height: 100vh; display: grid; place-items: center; }
        main { max-width: 40rem; padding: 2rem; }
        h1 { font-size: 1.3rem; margin: 0 0 .75rem; }
        pre { white-space: pre-wrap; font: 12px ui-monospace, monospace; line-height: 1.5; }
        .spin { width: 22px; height: 22px; border: 3px solid #8884; border-top-color: #888; border-radius: 50%;
                animation: s 1s linear infinite; margin-bottom: 1rem; }
        @keyframes s { to { transform: rotate(360deg); } }
        </style>
        <main>\(spinner ? "<div class=spin></div>" : "")<h1>\(escape(title))</h1><pre>\(escape(body))</pre></main>
        """
        webView.loadHTMLString(html, baseURL: nil)
    }

    // MARK: - web view

    private func isOurs(_ url: URL) -> Bool {
        url.scheme == "http" && url.host == "127.0.0.1" && url.port == port && port != nil
    }

    func webView(_ webView: WKWebView, decidePolicyFor action: WKNavigationAction,
                 decisionHandler: @escaping @MainActor (WKNavigationActionPolicy) -> Void) {
        if action.shouldPerformDownload { return decisionHandler(.download) }
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
        let folder = FileManager.default.urls(for: .downloadsDirectory, in: .userDomainMask)[0]
        let name = (suggestedFilename as NSString).deletingPathExtension, ext = (suggestedFilename as NSString).pathExtension
        var target = folder.appendingPathComponent(suggestedFilename)
        var n = 1
        while FileManager.default.fileExists(atPath: target.path) {
            n += 1
            target = folder.appendingPathComponent(ext.isEmpty ? "\(name) \(n)" : "\(name) \(n).\(ext)")
        }
        supervisor.log.info("download saved to \(target.path)")
        completionHandler(target)
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
        webView.reload()
    }

    func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
        guard let url = (error as NSError).userInfo[NSURLErrorFailingURLErrorKey] as? URL, isOurs(url) else { return }
        fail("The window could not load \(url.absoluteString): \(error.localizedDescription)")
    }

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        guard let url = webView.url, isOurs(url), !reportedFirstPage else { return }
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
            if let path = ProcessInfo.processInfo.environment["LOON_SPIKE_SNAPSHOT"] {
                webView.takeSnapshot(with: nil) { image, _ in
                    guard let tiff = image?.tiffRepresentation, let png = NSBitmapImageRep(data: tiff)?
                        .representation(using: .png, properties: [:]) else { return }
                    try? png.write(to: URL(fileURLWithPath: path))
                    self.supervisor.log.info("snapshot of the window written to \(path)")
                }
            }
            // Test only, as the snapshot is: a file of JavaScript run once in the page as an async
            // function body, its result logged. The spike's validation drives the setup form with it.
            if let path = ProcessInfo.processInfo.environment["LOON_SPIKE_WINDOW_SCRIPT"],
               let body = try? String(contentsOfFile: path, encoding: .utf8) {
                webView.callAsyncJavaScript(body, in: nil, in: .page) { result in
                    self.supervisor.log.info("window script: \((try? result.get()).map { "\($0)" } ?? "\(result)")")
                }
            }
        }
    }
}
