import AppKit
import WebKit

/// Local Find in Page using WebKit's public text finder. The page's filters and gated AI remain separate, explicit actions.
@MainActor
final class PageFindController: NSObject, NSSearchFieldDelegate, WKScriptMessageHandler {
    let view = NSVisualEffectView()
    private let query = NSSearchField()
    private let previous = NSButton()
    private let next = NSButton()
    private let status = NSTextField(labelWithString: "")
    private let matchCase = NSButton(checkboxWithTitle: "Match case", target: nil, action: nil)
    private let pageSearch = NSButton(title: "Go to page search", target: nil, action: nil)
    private let aiSearch = NSButton(title: "Go to AI search", target: nil, action: nil)
    private weak var webView: WKWebView?
    private weak var returnResponder: NSResponder?
    private var pending: DispatchWorkItem?
    private var generation = 0
    private var page: String?
    private var hasResult = false

    init(webView: WKWebView) {
        self.webView = webView
        super.init()
        let content = webView.configuration.userContentController
        content.add(self, contentWorld: .defaultClient, name: "pageFind")
        buildBar()
    }

    /// The shell replaces setup scripts on startup and service restart; restore this independent bridge with them.
    func installScript() {
        webView?.configuration.userContentController.addUserScript(
            WKUserScript(source: PageFindBridge.install, injectionTime: .atDocumentEnd,
                         forMainFrameOnly: true, in: .defaultClient))
    }

    var isVisible: Bool { !view.isHidden }

    private func buildBar() {
        view.material = .headerView
        view.blendingMode = .withinWindow
        view.isHidden = true
        query.placeholderString = "Find in page"
        query.setAccessibilityLabel("Find in page")
        query.setAccessibilityIdentifier("page-find-query")
        query.delegate = self
        query.sendsSearchStringImmediately = true
        query.sendsWholeSearchString = false
        query.setContentHuggingPriority(.defaultLow, for: .horizontal)
        query.widthAnchor.constraint(greaterThanOrEqualToConstant: 220).isActive = true
        previous.image = NSImage(systemSymbolName: "chevron.up", accessibilityDescription: "Previous match")
        next.image = NSImage(systemSymbolName: "chevron.down", accessibilityDescription: "Next match")
        previous.setAccessibilityLabel("Previous match")
        next.setAccessibilityLabel("Next match")
        for button in [previous, next] { button.bezelStyle = .rounded; button.target = self }
        previous.action = #selector(findPrevious)
        next.action = #selector(findNext)
        previous.toolTip = "Previous match (Shift-Return or ⇧⌘G)"
        next.toolTip = "Next match (Return or ⌘G)"
        previous.setAccessibilityIdentifier("page-find-previous")
        next.setAccessibilityIdentifier("page-find-next")
        matchCase.target = self
        matchCase.action = #selector(optionsChanged)
        let done = NSButton(title: "Done", target: self, action: #selector(close))
        done.bezelStyle = .rounded
        done.toolTip = "Close Find (Escape)"
        done.setAccessibilityIdentifier("page-find-close")
        status.font = .systemFont(ofSize: 11)
        status.lineBreakMode = .byTruncatingTail
        status.setAccessibilityIdentifier("page-find-status")
        status.setContentHuggingPriority(.defaultLow, for: .horizontal)
        for button in [pageSearch, aiSearch] {
            button.bezelStyle = .rounded
            button.controlSize = .small
            button.font = .systemFont(ofSize: 11)
            button.target = self
            button.isHidden = true
        }
        pageSearch.action = #selector(focusPageSearch)
        aiSearch.action = #selector(focusAISearch)
        pageSearch.toolTip = "Focus this page's search controls for results beyond the loaded text."
        aiSearch.toolTip = "Focus this page's existing AI search. Nothing is sent until you submit there."
        let row = NSStackView(views: [query, previous, next, matchCase, done])
        row.spacing = 6
        let detail = NSStackView(views: [status, pageSearch, aiSearch])
        detail.spacing = 8
        let scope = NSTextField(labelWithString: "Loaded page text only. Use page search for other results.")
        scope.font = .systemFont(ofSize: 10)
        scope.textColor = .secondaryLabelColor
        let stack = NSStackView(views: [row, detail, scope])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 4
        stack.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 12),
            stack.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -12),
            stack.topAnchor.constraint(equalTo: view.topAnchor, constant: 8),
            stack.bottomAnchor.constraint(equalTo: view.bottomAnchor, constant: -8),
            row.widthAnchor.constraint(equalTo: stack.widthAnchor),
            detail.widthAnchor.constraint(equalTo: stack.widthAnchor)
        ])
        resetStatus()
    }

    func show() {
        guard let webView, !webView.isHidden else { return }
        if isVisible { focusQuery(); return }
        returnResponder = webView.window?.firstResponder
        view.isHidden = false
        generation += 1
        let request = generation
        bridge("window.loonPageFind?.activate(true)") { _ in }
        refreshContext(changed: false)
        // Cmd-F can begin from selected page text. A retained query wins when the page has no selection.
        bridge("window.loonPageFind?.selection() || ''") { [weak self] result in
            guard let self, self.isVisible, self.generation == request else { return }
            if case .success(let value) = result, let selection = value as? String, !selection.isEmpty {
                self.query.stringValue = selection
            }
            self.focusQuery()
            self.search(backwards: false)
        }
    }

    private func focusQuery() {
        view.window?.makeFirstResponder(query)
        query.selectText(nil)
    }

    @objc func close() {
        guard isVisible else { return }
        pending?.cancel()
        generation += 1
        view.isHidden = true
        bridge("window.loonPageFind?.activate(false)") { _ in }
        // Leave the selected match available for copying. Closing Find does not modify the page or its filters.
        if let responder = returnResponder as? NSView, responder.window === webView?.window {
            webView?.window?.makeFirstResponder(responder)
        } else {
            webView?.window?.makeFirstResponder(webView)
        }
    }

    /// Hide stale search feedback when the native shell replaces the web page with startup or recovery.
    func suspend() {
        close()
        page = nil
        hasResult = false
    }

    @objc func findNext() { step(backwards: false) }
    @objc func findPrevious() { step(backwards: true) }

    private func step(backwards: Bool) {
        guard let webView, !webView.isHidden else { return }
        if !isVisible {
            returnResponder = webView.window?.firstResponder
            view.isHidden = false
            bridge("window.loonPageFind?.activate(true)") { _ in }
            refreshContext(changed: false)
        }
        if query.stringValue.isEmpty { focusQuery(); resetStatus(); return }
        search(backwards: backwards)
    }

    func useSelection() {
        guard let webView, !webView.isHidden else { return }
        if !isVisible { returnResponder = webView.window?.firstResponder; view.isHidden = false }
        bridge("window.loonPageFind?.activate(true)") { _ in }
        refreshContext(changed: false)
        bridge("window.loonPageFind?.selection() || ''") { [weak self] result in
            guard let self, self.isVisible else { return }
            if case .success(let value) = result, let selection = value as? String, !selection.isEmpty {
                self.query.stringValue = selection
                self.search(backwards: false)
            } else {
                self.say("Select text on the page first, then choose Use Selection for Find.")
            }
            self.focusQuery()
        }
    }

    func controlTextDidChange(_ notification: Notification) { scheduleSearch() }
    @objc private func optionsChanged() { scheduleSearch() }

    func control(_ control: NSControl, textView: NSTextView, doCommandBy commandSelector: Selector) -> Bool {
        if commandSelector == #selector(NSResponder.cancelOperation(_:)) { close(); return true }
        if commandSelector == #selector(NSResponder.insertNewline(_:)) {
            step(backwards: NSApp.currentEvent?.modifierFlags.contains(.shift) == true)
            return true
        }
        return false
    }

    private func scheduleSearch() {
        pending?.cancel()
        generation += 1
        hasResult = false
        if query.stringValue.isEmpty { resetStatus(); return }
        say("Finding…")
        let work = DispatchWorkItem { [weak self] in self?.search(backwards: false) }
        pending = work
        DispatchQueue.main.asyncAfter(deadline: .now() + .milliseconds(150), execute: work)
    }

    private func resetStatus() {
        previous.isEnabled = false
        next.isEnabled = false
        say("Type to find text on this page.")
    }

    private func search(backwards: Bool) {
        pending?.cancel()
        generation += 1
        let request = generation
        guard let webView, isVisible, !query.stringValue.isEmpty else { resetStatus(); return }
        previous.isEnabled = true
        next.isEnabled = true
        let configuration = WKFindConfiguration()
        configuration.caseSensitive = matchCase.state == .on
        configuration.backwards = backwards
        configuration.wraps = true
        // WebKit finds rendered text, including text split across inline elements, and scrolls the match into view.
        webView.find(query.stringValue, configuration: configuration) { [weak self] result in
            guard let self, self.isVisible, self.generation == request else { return }
            self.hasResult = true
            self.say(result.matchFound ? "Match found. Return: next · Shift-Return: previous."
                                      : "No matches on this page. Other results may be available through page search.")
        }
    }

    private func say(_ message: String) {
        guard status.stringValue != message else { return }
        status.stringValue = message
        status.toolTip = message
        if isVisible {
            NSAccessibility.post(element: status, notification: .valueChanged)
        }
    }

    private func bridge(_ script: String, completion: @escaping @MainActor @Sendable (Result<Any, Error>) -> Void) {
        webView?.evaluateJavaScript(script, in: nil, in: .defaultClient, completionHandler: completion)
    }

    func userContentController(_ userContentController: WKUserContentController, didReceive message: WKScriptMessage) {
        guard message.frameInfo.isMainFrame, let event = message.body as? String,
              event == "ready" || event == "changed", isVisible else { return }
        if event == "ready" { bridge("window.loonPageFind?.activate(true)") { _ in } }
        refreshContext(changed: true)
    }

    private func refreshContext(changed: Bool) {
        bridge("window.loonPageFind?.context() || {}") { [weak self] result in
            guard let self, self.isVisible else { return }
            switch result {
            case .success(let value):
                guard let context = value as? [String: Any] else { return }
                self.pageSearch.isHidden = context["search"] as? Bool != true
                self.aiSearch.isHidden = context["ai"] as? Bool != true
                let nextPage = context["page"] as? String
                let navigated = self.page != nil && self.page != nextPage
                self.page = nextPage
                if navigated {
                    self.scheduleSearch()
                } else if changed && self.hasResult {
                    self.generation += 1
                    self.hasResult = false
                    self.say("Page content changed. Press Return to find in the updated page.")
                }
            case .failure:
                self.pageSearch.isHidden = true
                self.aiSearch.isHidden = true
                // Native text finding still works when a page does not expose its richer search controls.
            }
        }
    }

    @objc private func focusPageSearch() { focusPageControl("search") }
    @objc private func focusAISearch() { focusPageControl("ai") }

    private func focusPageControl(_ kind: String) {
        guard let webView else { return }
        webView.window?.makeFirstResponder(webView)
        bridge("window.loonPageFind?.focus('\(kind)') || false") { [weak self] result in
            guard let self else { return }
            if case .success(let value) = result, value as? Bool == true {
                self.returnResponder = nil
                self.close()
            } else {
                self.focusQuery()
                self.say("That search control is no longer available. Reopen Find after the page finishes loading.")
                self.refreshContext(changed: false)
            }
        }
    }
}
