import AppKit
import WebKit

/// Exercises the actual shell's toolbar, menu shortcuts, SPA history, appearance and JavaScript confirmation sheets.
@MainActor
enum NavigationHarness {
    private static func views(_ view: NSView) -> [NSView] { [view] + view.subviews.flatMap(views) }
    private static func check(_ condition: Bool, _ message: String) throws {
        if !condition { throw HarnessFailure.failed(message) }
    }
    private static func wait(_ message: String, _ condition: @escaping () -> Bool) async throws {
        let deadline = Date().addingTimeInterval(8)
        while !condition() {
            if Date() > deadline { throw HarnessFailure.failed("Timed out: \(message)") }
            try await Task.sleep(for: .milliseconds(25))
        }
    }
    private static func buttons(_ web: WKWebView) throws -> (back: NSButton, forward: NSButton) {
        let controls = web.window?.toolbar?.items.compactMap(\.view).flatMap(views).compactMap { $0 as? NSButton } ?? []
        guard let back = controls.first(where: { $0.accessibilityIdentifier() == "navigation-back" }),
              let forward = controls.first(where: { $0.accessibilityIdentifier() == "navigation-forward" }) else {
            throw HarnessFailure.failed("The native Back/Forward toolbar controls are missing")
        }
        return (back, forward)
    }
    private static func menuItem(_ title: String) throws -> NSMenuItem {
        guard let view = NSApp.mainMenu?.items.first(where: { $0.submenu?.title == "View" })?.submenu,
              let item = view.items.first(where: { $0.title == title }) else {
            throw HarnessFailure.failed("Missing View menu item: \(title)")
        }
        return item
    }
    private static func action(_ title: String, delegate: AppDelegate) throws {
        let item = try menuItem(title)
        guard let selector = item.action, delegate.validateMenuItem(item) else {
            throw HarnessFailure.failed("Disabled View action: \(title)")
        }
        try check(NSApp.sendAction(selector, to: delegate, from: item), "View action was not dispatched: \(title)")
    }
    private static func shortcut(_ title: String, delegate: AppDelegate, web: WKWebView) throws {
        let item = try menuItem(title)
        let character = title == "Back" ? "[" : "]"
        try check(item.keyEquivalent == character && item.keyEquivalentModifierMask == .command,
                  "\(title) must use its standard Command-bracket shortcut")
        web.window?.makeKeyAndOrderFront(nil)
        web.window?.makeFirstResponder(web)
        let previous = NSApp.delegate
        NSApp.delegate = delegate
        defer { NSApp.delegate = previous }
        let event = NSEvent.keyEvent(with: .keyDown, location: .zero, modifierFlags: .command, timestamp: 0,
                                    windowNumber: web.window!.windowNumber, context: nil, characters: character,
                                    charactersIgnoringModifiers: character, isARepeat: false,
                                    keyCode: title == "Back" ? 33 : 30)!
        try check(NSApp.mainMenu!.performKeyEquivalent(with: event), "Actual \(title) shortcut did not dispatch")
    }
    private static func string(_ script: String, web: WKWebView) async throws -> String {
        try await web.evaluateJavaScript(script) as? String ?? ""
    }
    private static func path(_ web: WKWebView) -> String {
        guard let url = web.url else { return "" }
        return url.path + (url.query.map { "?" + $0 } ?? "") + (url.fragment.map { "#" + $0 } ?? "")
    }
    private static func appearance(_ web: WKWebView) -> NSAppearance.Name? {
        web.window?.effectiveAppearance.bestMatch(from: [.aqua, .darkAqua])
    }

    static func assertDisabled(delegate: AppDelegate, web: WKWebView, reason: String) throws {
        let controls = try buttons(web)
        try check(!controls.back.isEnabled && !controls.forward.isEnabled, "History toolbar enabled during \(reason)")
        try check(!delegate.validateMenuItem(menuItem("Back")) && !delegate.validateMenuItem(menuItem("Forward")),
                  "History menu enabled during \(reason)")
        try check(!web.allowsBackForwardNavigationGestures, "History gestures enabled during \(reason)")
    }

    static func run(delegate: AppDelegate, web: WKWebView, supervisor: Supervisor) async throws {
        let controls = try buttons(web)
        try check(!controls.back.isEnabled && !controls.forward.isEnabled, "Fresh page already has enabled history controls")
        try check(!delegate.validateMenuItem(menuItem("Back")) && !delegate.validateMenuItem(menuItem("Forward")),
                  "Fresh page already has enabled history menu actions")
        try check(web.allowsBackForwardNavigationGestures, "Healthy page does not allow native history gestures")
        let toolbar = web.window!.toolbar!
        try check(toolbar.items.contains { $0.label == "Back" } && toolbar.items.contains { $0.label == "Forward" },
                  "Native history toolbar labels are missing")
        try await exerciseWindowChrome(web: web)
        let start = URL(string: "/navigation/one", relativeTo: web.url!)!.absoluteURL
        web.load(URLRequest(url: start))
        try await wait("navigation fixture loads") { web.url == start && !web.isLoading && !web.isHidden }
        let marker = try await string("document.body.dataset.request", web: web)
        try check(!marker.isEmpty, "Navigation fixture response marker is missing")
        _ = try await web.evaluateJavaScript("document.getElementById('review-note').value = 'Unsaved fixture note'; document.getElementById('next-route').click()")
        try await wait("SPA link updates native history") {
            path(web) == "/navigation/two?filter=alpha#details" && controls.back.isEnabled && !controls.forward.isEnabled
        }
        try check(delegate.validateMenuItem(menuItem("Back")), "SPA history did not enable the Back menu")
        controls.back.performClick(nil)
        try await wait("native toolbar Back returns through SPA history") { path(web) == "/navigation/one" && controls.forward.isEnabled }
        try check(try await string("document.getElementById('route').textContent", web: web) == "/navigation/one",
                  "Native Back did not dispatch the SPA popstate render")
        try shortcut("Forward", delegate: delegate, web: web)
        try await wait("Command-] restores the query and fragment") { path(web) == "/navigation/two?filter=alpha#details" && !controls.forward.isEnabled }
        try check(try await string("document.body.dataset.request", web: web) == marker && !web.isHidden,
                  "SPA history reloaded or hid the document")
        try check(try await string("document.getElementById('review-note').value", web: web) == "Unsaved fixture note",
                  "SPA history lost unsaved in-document state")
        print("PASS: toolbar Back and Command-] traverse SPA history, preserving query, fragment and unsaved document state")

        let beforeReplace = web.backForwardList.backList.count
        _ = try await web.evaluateJavaScript("document.getElementById('replace-query').click()")
        try await wait("replaceState updates the native current URL") { path(web) == "/navigation/two?filter=beta#details" }
        try check(web.backForwardList.backList.count == beforeReplace, "replaceState added a history entry")
        try shortcut("Back", delegate: delegate, web: web)
        try await wait("Command-[ returns to the previous route") { path(web) == "/navigation/one" && controls.forward.isEnabled }
        _ = try await web.evaluateJavaScript("document.getElementById('branch-route').click()")
        try await wait("new navigation clears Forward") { path(web) == "/navigation/branch?filter=gamma" && !controls.forward.isEnabled }
        try check(!delegate.validateMenuItem(menuItem("Forward")), "Forward menu remained enabled after branching history")
        print("PASS: replaceState changes the current entry and a new route clears forward history")

        try await exerciseFindRouteChange(delegate: delegate, web: web)
        _ = try await web.evaluateJavaScript("document.documentElement.dataset.loonTheme = 'dark'")
        try await wait("native window follows dark app theme") { appearance(web) == .darkAqua }
        _ = try await web.evaluateJavaScript("document.documentElement.dataset.loonTheme = 'light'")
        try await wait("native window follows light app theme") { appearance(web) == .aqua }
        try await visualCheckpoint("light", web: web)
        _ = try await web.evaluateJavaScript("document.documentElement.dataset.loonTheme = 'dark'")
        try await wait("dark appearance restored") { appearance(web) == .darkAqua }
        try await visualCheckpoint("dark", web: web)
        // Deliberately send from the same isolated world in a child frame to exercise native validation.
        web.configuration.userContentController.addUserScript(WKUserScript(
            source: "if (window.top !== window) window.webkit.messageHandlers.windowAppearance.postMessage('light');",
            injectionTime: .atDocumentEnd, forMainFrameOnly: false, in: .defaultClient))
        _ = try await web.evaluateJavaScript("document.documentElement.dataset.loonTheme = 'invalid'; window.childThemeLoaded = false; document.getElementById('child-theme').src = '/navigation/frame?theme=light'")
        let themeDeadline = Date().addingTimeInterval(8)
        while try await string("String(window.childThemeLoaded)", web: web) != "true" {
            if Date() > themeDeadline { throw HarnessFailure.failed("Child-frame theme fixture did not load") }
            try await Task.sleep(for: .milliseconds(25))
        }
        try await Task.sleep(for: .milliseconds(100))
        try check(appearance(web) == .darkAqua, "Invalid or child-frame theme changed the main window")
        print("PASS: native appearance follows app light/dark changes and ignores invalid values and child-frame themes")

        try await exerciseConfirmation(web: web, activation: "Return", expected: "false")
        try await exerciseConfirmation(web: web, activation: "Escape", expected: "false")
        try await exerciseConfirmation(web: web, activation: "Continue", expected: "true")
        try await exercisePageEscape(web: web)
        _ = try await web.evaluateJavaScript("window.childConfirmResult = null; document.getElementById('child-theme').src = '/navigation/frame?confirm=1'")
        let childDeadline = Date().addingTimeInterval(8)
        while try await string("window.childConfirmResult", web: web) != "false" {
            if web.window?.attachedSheet != nil { throw HarnessFailure.failed("A child frame opened a native confirmation sheet") }
            if Date() > childDeadline { throw HarnessFailure.failed("Child-frame confirmation was not rejected") }
            try await Task.sleep(for: .milliseconds(25))
        }
        print("PASS: native confirmation handles Return/Escape/Continue, ignores modified Escape, cleans up its handler, and rejects child frames")

        let routeBeforeReload = path(web)
        try action("Reload Window", delegate: delegate)
        try await wait("reload preserves the latest SPA query route") { !web.isLoading && !web.isHidden && path(web) == routeBeforeReload }
        try check(try await string("document.body.dataset.request", web: web) != marker, "Reload did not request a new document")
        print("PASS: Reload Window uses the latest SPA route and query")
        let previousDocument = try await string("document.body.dataset.request", web: web)
        var disabledForRestart = false
        let restartObservation = controls.back.observe(\.isEnabled, options: [.new]) { _, change in
            if change.newValue == false { MainActor.assumeIsolated { disabledForRestart = true } }
        }
        let update = NSApp.mainMenu!.items.first!.submenu!.items.first { $0.title == "Check for Updates Daily" }!
        NSApp.sendAction(update.action!, to: delegate, from: update)
        try await wait("service restart reloads the navigation page") { supervisor.restartCount == 1 && !web.isHidden && !web.isLoading }
        let deadline = Date().addingTimeInterval(8)
        while try await string("document.body.dataset.request", web: web) == previousDocument {
            if Date() > deadline { throw HarnessFailure.failed("Service restart did not fetch a new navigation document") }
            try await Task.sleep(for: .milliseconds(25))
        }
        _ = try await web.evaluateJavaScript("document.documentElement.dataset.loonTheme = 'dark'")
        try await wait("theme bridge survives service restart") { appearance(web) == .darkAqua }
        _ = try await web.evaluateJavaScript("document.getElementById('next-route').click()")
        try await wait("history observation survives service restart") { path(web) == "/navigation/two?filter=alpha#details" && controls.back.isEnabled }
        withExtendedLifetime(restartObservation) {}
        try check(disabledForRestart, "Restart never disabled the previously enabled Back control")
        try check(web.allowsBackForwardNavigationGestures, "Native history gestures did not recover after restart")
        print("PASS: history controls and the theme bridge survive local-service restart")
    }

    private static func exerciseWindowChrome(web: WKWebView) async throws {
        guard let window = web.window, let content = window.contentView else {
            throw HarnessFailure.failed("Navigation fixture has no native window")
        }
        try check(window.styleMask.contains([.titled, .closable, .miniaturizable, .resizable]),
                  "Navigation changed the standard Mac window style")
        try check(window.toolbarStyle == .unifiedCompact && window.toolbar?.isVisible == true,
                  "Navigation toolbar is not visible in the compact native title bar")
        window.makeKeyAndOrderFront(nil)
        let originalSize = content.frame.size
        window.setContentSize(window.contentMinSize)
        content.superview?.layoutSubtreeIfNeeded()
        try await Task.sleep(for: .milliseconds(100))
        for kind in [NSWindow.ButtonType.closeButton, .miniaturizeButton, .zoomButton] {
            guard let button = window.standardWindowButton(kind) else {
                throw HarnessFailure.failed("A standard traffic-light control is missing")
            }
            let frame = button.convert(button.bounds, to: nil)
            try check(!button.isHiddenOrHasHiddenAncestor && frame.width > 0 && frame.height > 0,
                      "A standard traffic-light control is hidden or collapsed")
            try check(frame.minX >= 0 && frame.maxX <= window.frame.width && frame.maxY <= window.frame.height,
                      "A standard traffic-light control falls outside the window")
        }
        let controls = try buttons(web)
        for button in [controls.back, controls.forward] {
            let frame = button.convert(button.bounds, to: nil)
            try check(button.bounds.width >= 18 && button.bounds.height >= 18 &&
                      button.visibleRect.width >= button.bounds.width - 1 &&
                      button.visibleRect.height >= button.bounds.height - 1,
                      "A navigation button is collapsed or clipped at minimum window size")
            try check(frame.minX >= 0 && frame.maxX <= window.frame.width &&
                      frame.minY >= window.contentLayoutRect.maxY - 1,
                      "A navigation button overlaps page content or falls outside the window")
        }
        let contentFrame = content.convert(content.bounds, to: nil)
        let pageFrame = web.convert(web.bounds, to: nil)
        try check(contentFrame.maxY <= window.contentLayoutRect.maxY + 1 &&
                  pageFrame.maxY <= window.contentLayoutRect.maxY + 1 && web.bounds.height > 250,
                  "The page extends under native chrome or collapses at minimum window size")
        window.setContentSize(originalSize)
        print("PASS: standard traffic lights, native toolbar and unobscured page remain usable at minimum window size")
    }

    private static func visualCheckpoint(_ name: String, web: WKWebView) async throws {
        guard ProcessInfo.processInfo.environment["LOONINSPECT_TEST_VISUAL_CHECKPOINTS"] == "1",
              let directory = ProcessInfo.processInfo.environment["LOONINSPECT_TEST_DIR"] else { return }
        let folder = URL(fileURLWithPath: directory, isDirectory: true)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        let ready = folder.appendingPathComponent("navigation-\(name).ready")
        let proceed = folder.appendingPathComponent("navigation-\(name).continue")
        web.window?.setContentSize(NSSize(width: 900, height: 650))
        web.window?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        try await Task.sleep(for: .milliseconds(200))
        try name.write(to: ready, atomically: true, encoding: .utf8)
        print("VISUAL CHECKPOINT: \(ready.path)")
        fflush(stdout)
        let deadline = Date().addingTimeInterval(45)
        while !FileManager.default.fileExists(atPath: proceed.path) {
            if Date() > deadline { throw HarnessFailure.failed("Visual checkpoint was not released: \(proceed.path)") }
            try await Task.sleep(for: .milliseconds(100))
        }
    }

    private static func exerciseFindRouteChange(delegate: AppDelegate, web: WKWebView) async throws {
        let content = web.window!.contentView!
        guard let query = views(content).compactMap({ $0 as? NSSearchField }).first,
              let status = views(content).compactMap({ $0 as? NSTextField }).first(where: { $0.accessibilityIdentifier() == "page-find-status" }),
              let done = views(content).compactMap({ $0 as? NSButton }).first(where: { $0.accessibilityIdentifier() == "page-find-close" }) else {
            throw HarnessFailure.failed("Find controls missing from navigation fixture")
        }
        NSApp.sendAction(NSSelectorFromString("openFind"), to: delegate, from: nil)
        query.stringValue = "history fixture needle"
        query.delegate?.controlTextDidChange?(Notification(name: NSControl.textDidChangeNotification, object: query))
        try await wait("Find matches before route-only navigation") { status.stringValue.hasPrefix("Match found.") }
        _ = try await web.evaluateJavaScript("document.getElementById('find-text').textContent = 'replacement content'")
        try await wait("Find invalidates after content mutation") { status.stringValue.hasPrefix("Page content changed.") }
        // No DOM event/mutation accompanies this push; URL observation must recheck the retained query itself.
        _ = try await web.evaluateJavaScript("history.pushState({}, '', '/navigation/branch?filter=delta')")
        try await wait("route-only navigation rechecks Find") { status.stringValue.hasPrefix("No matches on this page.") }
        try check(!query.isHiddenOrHasHiddenAncestor && query.stringValue == "history fixture needle", "Navigation closed or cleared Find")
        done.performClick(nil)
        print("PASS: a route-only URL change rechecks the visible Find bar's retained query")
    }

    private static func postKey(_ name: String, window: NSWindow, modifiers: NSEvent.ModifierFlags = []) {
        let character = name == "Return" ? "\r" : "\u{1b}"
        let event = NSEvent.keyEvent(with: .keyDown, location: .zero, modifierFlags: modifiers,
                                    timestamp: ProcessInfo.processInfo.systemUptime, windowNumber: window.windowNumber,
                                    context: nil, characters: character, charactersIgnoringModifiers: character,
                                    isARepeat: false, keyCode: name == "Return" ? 36 : 53)!
        NSApp.postEvent(event, atStart: false)
    }

    private static func exercisePageEscape(web: WKWebView) async throws {
        let window = web.window!
        window.makeKeyAndOrderFront(nil)
        window.makeFirstResponder(web)
        try await wait("workspace is key after confirmation") { NSApp.keyWindow === window }
        _ = try await web.evaluateJavaScript("""
            window.outsideEscapeReceived = false;
            document.addEventListener('keydown', event => {
              window.outsideEscapeReceived = event.key === 'Escape';
              event.preventDefault();
            }, {once: true});
            document.getElementById('review-note').focus();
            """)
        postKey("Escape", window: window)
        let deadline = Date().addingTimeInterval(8)
        while try await string("String(window.outsideEscapeReceived)", web: web) != "true" {
            if Date() > deadline { throw HarnessFailure.failed("Escape did not reach the page after the confirmation sheet closed") }
            try await Task.sleep(for: .milliseconds(25))
        }
    }

    private static func exerciseConfirmation(web: WKWebView, activation: String, expected: String) async throws {
        _ = try await web.evaluateJavaScript("window.confirmResult = null; setTimeout(() => { window.confirmResult = String(confirm('Discard fixture review notes?')); }, 0); true")
        try await wait("JavaScript confirm presents a native sheet") { web.window?.attachedSheet != nil }
        guard let sheet = web.window?.attachedSheet, let content = sheet.contentView else {
            throw HarnessFailure.failed("Confirmation sheet has no content")
        }
        let controls = views(content).compactMap { $0 as? NSButton }
        guard controls.contains(where: { $0.title == "Cancel" }),
              let proceed = controls.first(where: { $0.title == "Continue" }) else {
            throw HarnessFailure.failed("Confirmation sheet lacks Cancel/Continue")
        }
        sheet.makeKeyAndOrderFront(nil)
        try await wait("confirmation sheet is visible and key") { sheet.isVisible && NSApp.keyWindow === sheet }
        if activation == "Continue" {
            proceed.performClick(nil)
        } else {
            if activation == "Escape" {
                postKey("Escape", window: sheet, modifiers: [.shift])
                try await Task.sleep(for: .milliseconds(200))
                try check(web.window?.attachedSheet === sheet, "Modified Escape cancelled the confirmation")
            }
            postKey(activation, window: sheet)
        }
        try await wait("native confirmation sheet closes after \(activation)") { web.window?.attachedSheet == nil }
        let deadline = Date().addingTimeInterval(8)
        while try await string("window.confirmResult", web: web) != expected {
            if Date() > deadline { throw HarnessFailure.failed("Native confirmation returned the wrong JavaScript result for \(activation)") }
            try await Task.sleep(for: .milliseconds(25))
        }
    }
}
