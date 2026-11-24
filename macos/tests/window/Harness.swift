import AppKit
import WebKit
import ObjectiveC

// These substitutions affect only this isolated test executable, never production source.
extension WKWebsiteDataStore {
    @objc class func isolatedTestDataStore() -> WKWebsiteDataStore { .nonPersistent() }
}
extension NSWindow {
    @objc func isolatedTestAutosave(_ name: String) -> Bool { false }
}

enum HarnessFailure: Error, CustomStringConvertible {
    case failed(String)
    var description: String { switch self { case .failed(let message): return message } }
}

@MainActor
final class HarnessRunner: NSObject, NSApplicationDelegate {
    private var delegates: [AppDelegate] = []
    private var windows: [NSWindow] = []
    private let port = Int(ProcessInfo.processInfo.environment["LOONINSPECT_TEST_PORT"]!)!
    private let directory = URL(fileURLWithPath: ProcessInfo.processInfo.environment["LOONINSPECT_TEST_DIR"]!)

    func applicationDidFinishLaunching(_ notification: Notification) {
        Task { @MainActor in
            do {
                try await exerciseWindowRecovery()
                try await exerciseLateStartup()
                try await exerciseUpdateCheckSwitch()
                try await exerciseFind()
                try await exerciseNavigation()
                windows.forEach { $0.orderOut(nil) }
                print("PASS: real-AppDelegate window, lifecycle, Find and navigation regression checks complete")
                fflush(stdout)
                exit(0)
            } catch {
                windows.forEach { $0.orderOut(nil) }
                fputs("FAIL: \(error)\n", stderr)
                exit(1)
            }
        }
    }

    private func check(_ condition: @autoclosure () -> Bool, _ message: String) throws {
        if !condition() { throw HarnessFailure.failed(message) }
    }
    private func eventually(_ message: String, timeout: TimeInterval = 15,
                            condition: @escaping @MainActor () -> Bool) async throws {
        let deadline = Date().addingTimeInterval(timeout)
        while !condition() {
            if Date() > deadline { throw HarnessFailure.failed("Timed out: \(message)") }
            try await Task.sleep(for: .milliseconds(25))
        }
    }
    private func views(_ view: NSView) -> [NSView] { [view] + view.subviews.flatMap(views) }
    private func heading(_ status: StatusView) -> String {
        views(status).compactMap { $0 as? NSTextField }.first { ($0.font?.pointSize ?? 0) >= 20 }?.stringValue ?? ""
    }
    private func menuItem(_ action: String) -> NSMenuItem {
        NSMenuItem(title: action, action: NSSelectorFromString(action), keyEquivalent: "")
    }
    private func launch(_ supervisor: Supervisor) throws -> (AppDelegate, WKWebView, StatusView) {
        let previous = Set(NSApp.windows.map(ObjectIdentifier.init))
        let delegate = AppDelegate(supervisor: supervisor)
        delegates.append(delegate)
        delegate.applicationDidFinishLaunching(Notification(name: NSApplication.didFinishLaunchingNotification))
        guard let window = NSApp.windows.first(where: { !previous.contains(ObjectIdentifier($0)) && $0.title == "LoonInspect" }),
              let content = window.contentView,
              let web = views(content).compactMap({ $0 as? WKWebView }).first,
              let status = views(content).compactMap({ $0 as? StatusView }).first else {
            throw HarnessFailure.failed("Actual delegate did not create its expected window/views")
        }
        windows.append(window)
        window.orderOut(nil)
        try NavigationHarness.assertDisabled(delegate: delegate, web: web, reason: "startup")
        try check(!web.configuration.websiteDataStore.isPersistent, "WebKit data store must be ephemeral")
        try check(window.frameAutosaveName.isEmpty, "Window-frame autosaving must be disabled")
        return (delegate, web, status)
    }
    private func requestMarker(_ web: WKWebView) async throws -> String {
        try await web.evaluateJavaScript("document.body.dataset.request") as? String ?? ""
    }
    private func pageError(_ url: URL, code: Int = NSURLErrorCannotConnectToHost) -> NSError {
        NSError(domain: NSURLErrorDomain, code: code,
                userInfo: [NSURLErrorFailingURLErrorKey: url, NSLocalizedDescriptionKey: "Isolated test navigation error"])
    }

    private func exerciseWindowRecovery() async throws {
        let supervisor = Supervisor(port: port, directory: directory)
        let (delegate, web, status) = try launch(supervisor)
        let base = URL(string: "http://127.0.0.1:\(port)/")!
        try await eventually("initial dummy page loads") { web.url == base && !web.isLoading && !web.isHidden && status.isHidden }

        delegate.webView(web, didFailProvisionalNavigation: nil, withError: pageError(base, code: NSURLErrorCancelled))
        try check(!web.isHidden && status.isHidden && supervisor.stopCount == 0, "Cancelled navigation changed the healthy window")
        print("PASS: cancelled provisional navigation is ignored")

        let route = base.appendingPathComponent("assessment/demo")
        web.load(URLRequest(url: route))
        try await eventually("dummy route loads") { web.url == route && !web.isLoading && status.isHidden }
        let before = try await requestMarker(web)
        try check(!before.isEmpty, "Dummy server response marker missing")
        delegate.webView(web, didFailProvisionalNavigation: nil, withError: pageError(route))
        try check(web.isHidden && !status.isHidden && heading(status) == "The window could not load", "Page failure did not present recovery")
        try NavigationHarness.assertDisabled(delegate: delegate, web: web, reason: "page recovery")
        try check(delegate.validateMenuItem(menuItem("reload")), "Recovery reload should remain enabled")
        guard let reload = views(status).compactMap({ $0 as? NSButton }).first(where: { $0.title == "Reload Window" }) else {
            throw HarnessFailure.failed("Actual recovery button missing")
        }
        reload.performClick(nil)
        try await eventually("reload returns to original local route") { web.url == route && !web.isLoading && !web.isHidden && status.isHidden }
        let after = try await requestMarker(web)
        try check(after != before, "Reload did not fetch the local page again")
        print("PASS: page failure → actual Reload button restores local route with a new response")

        delegate.webView(web, didFail: nil, withError: pageError(route))
        try check(!status.isHidden && heading(status) == "The window could not load", "Committed navigation failure lacked recovery")
        reload.performClick(nil)
        try await eventually("committed failure reload recovers") { !web.isLoading && !web.isHidden && status.isHidden }
        print("PASS: committed-navigation failure uses the same recovery")

        supervisor.onUnexpectedExit?("Fixture service stopped.")
        try await eventually("failed service is stopped") { supervisor.stopCount == 1 && !status.isHidden }
        try NavigationHarness.assertDisabled(delegate: delegate, web: web, reason: "service failure")
        try check(heading(status) == "The local service stopped", "Runtime failure used a startup heading")
        try check(!delegate.validateMenuItem(menuItem("reload")), "Reload enabled after service stopped")
        try check(!delegate.validateMenuItem(menuItem("openInBrowser")), "Browser enabled after service stopped")
        supervisor.onUnexpectedExit?("Duplicate fixture exit.")
        supervisor.onProgress?("Late progress", "Must not replace the failure")
        try await Task.sleep(for: .milliseconds(150))
        try check(supervisor.stopCount == 1 && heading(status) == "The local service stopped", "Duplicate event repeated cleanup or overwrote failure")
        print("PASS: service exit disables actions, stops once, and ignores duplicate/late progress")
    }

    private func exerciseLateStartup() async throws {
        let supervisor = Supervisor(port: port, directory: directory, delayedStart: true)
        let (delegate, web, status) = try launch(supervisor)
        try await eventually("delayed startup enters fake supervisor") { supervisor.startEntered }
        supervisor.onUnexpectedExit?("Fixture startup service exited.")
        try await eventually("startup failure is shown and stopped") {
            supervisor.stopCount == 1 && self.heading(status) == "LoonInspect could not start"
        }
        supervisor.releaseStart.signal()
        try await eventually("fake start returns after failure") { supervisor.startReturned }
        try await Task.sleep(for: .milliseconds(250))
        try check(web.url == nil && !status.isHidden && heading(status) == "LoonInspect could not start", "Late startup callback overwrote failed state")
        try check(supervisor.stopCount == 1 && !delegate.validateMenuItem(menuItem("reload")), "Late startup reenabled actions or repeated stop")
        print("PASS: late successful startup callback cannot replace the failure")
    }

    private func exerciseFind() async throws {
        let (delegate, web, status) = try launch(Supervisor(port: port, directory: directory))
        try await eventually("find fixture loads") { web.url != nil && !web.isLoading && !web.isHidden && status.isHidden }
        try await FindHarness.run(delegate: delegate, web: web)
    }

    private func exerciseNavigation() async throws {
        let supervisor = Supervisor(port: port, directory: directory)
        let (delegate, web, status) = try launch(supervisor)
        try await eventually("initial navigation page loads") { web.url != nil && !web.isLoading && !web.isHidden && status.isHidden }
        try await NavigationHarness.run(delegate: delegate, web: web, supervisor: supervisor)
    }

    private func exerciseUpdateCheckSwitch() async throws {
        let supervisor = Supervisor(port: port, directory: directory)
        let (delegate, web, status) = try launch(supervisor)
        try await eventually("initial dummy page loads") { web.url != nil && !web.isLoading && !web.isHidden && status.isHidden }
        guard let item = NSApp.mainMenu?.items.first?.submenu?.items.first(where: { $0.title == "Check for Updates Daily" }),
              let action = item.action else { throw HarnessFailure.failed("Check for Updates Daily is not in the app menu") }
        try check(delegate.validateMenuItem(item) && item.state == .on, "Check for Updates Daily should start enabled and on")
        let before = try await requestMarker(web)
        NSApp.sendAction(action, to: delegate, from: item)
        try await eventually("the change restarts the server, then reloads the page") {
            supervisor.restartCount == 1 && !web.isLoading && !web.isHidden && status.isHidden
        }
        let after = try await requestMarker(web)
        try check(after != before && !supervisor.checksForUpdatesDaily && delegate.validateMenuItem(item) && item.state == .off,
                  "The choice should be stored off, the item read off, and the page be loaded again")
        supervisor.updateCheckSetByEnvironment = true
        try check(!delegate.validateMenuItem(item), "An UPDATE_CHECK in the app's environment should dim the item")
        print("PASS: Check for Updates Daily stores the choice, restarts the server once, and reloads the page")
    }
}

@main
enum Harness {
    @MainActor static func main() {
        guard let defaultStore = class_getClassMethod(WKWebsiteDataStore.self, NSSelectorFromString("defaultDataStore")),
              let ephemeralStore = class_getClassMethod(WKWebsiteDataStore.self, #selector(WKWebsiteDataStore.isolatedTestDataStore)),
              let autosave = class_getInstanceMethod(NSWindow.self, NSSelectorFromString("setFrameAutosaveName:")),
              let noAutosave = class_getInstanceMethod(NSWindow.self, #selector(NSWindow.isolatedTestAutosave(_:))) else {
            fputs("FAIL: could not establish isolated WebKit/preferences behavior\n", stderr)
            exit(1)
        }
        method_exchangeImplementations(defaultStore, ephemeralStore)
        method_exchangeImplementations(autosave, noAutosave)
        let app = NSApplication.shared
        app.setActivationPolicy(.accessory)
        let runner = HarnessRunner()
        app.delegate = runner
        withExtendedLifetime(runner) { app.run() }
    }
}
