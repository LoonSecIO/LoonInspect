import AppKit
import WebKit

/// Native history and appearance for the embedded workspace; never reloads a route to go Back or Forward.
@MainActor
final class WindowNavigationController: NSObject, NSToolbarDelegate, WKScriptMessageHandler {
    private weak var webView: WKWebView?
    private weak var window: NSWindow?
    private let isLocalURL: (URL) -> Bool
    var onLocalURLChange: ((URL) -> Void)?
    private var available = false
    private var lastURL: URL?
    private var observations: [NSKeyValueObservation] = []
    private let backButton = NSButton()
    private let forwardButton = NSButton()
    private let backID = NSToolbarItem.Identifier("navigation-back")
    private let forwardID = NSToolbarItem.Identifier("navigation-forward")
    private var items: [NSToolbarItem.Identifier: NSToolbarItem] = [:]

    init(webView: WKWebView, window: NSWindow, isLocalURL: @escaping (URL) -> Bool) {
        self.webView = webView; self.window = window; self.isLocalURL = isLocalURL
        super.init()
        configure(backButton, label: "Back", symbol: "chevron.left", identifier: backID, action: #selector(back))
        configure(forwardButton, label: "Forward", symbol: "chevron.right", identifier: forwardID, action: #selector(forward))
        let toolbar = NSToolbar(identifier: "LoonInspectNavigation")
        toolbar.delegate = self
        toolbar.displayMode = .iconOnly
        toolbar.allowsUserCustomization = false
        toolbar.autosavesConfiguration = false
        window.toolbarStyle = .unifiedCompact
        window.titleVisibility = .hidden
        window.toolbar = toolbar
        webView.configuration.userContentController.add(self, contentWorld: .defaultClient, name: "windowAppearance")
        observations = [
            webView.observe(\.canGoBack, options: [.initial, .new]) { [weak self] _, _ in
                Task { @MainActor in self?.refresh() }
            },
            webView.observe(\.canGoForward, options: [.new]) { [weak self] _, _ in
                Task { @MainActor in self?.refresh() }
            },
            webView.observe(\.url, options: [.new]) { [weak self] _, _ in
                Task { @MainActor in self?.refresh() }
            },
            webView.observe(\.isLoading, options: [.new]) { [weak self] _, _ in
                Task { @MainActor in self?.refresh() }
            },
        ]
        refresh()
    }

    private func configure(_ button: NSButton, label: String, symbol: String,
                           identifier: NSToolbarItem.Identifier, action: Selector) {
        button.image = NSImage(systemSymbolName: symbol, accessibilityDescription: label)
        button.imagePosition = .imageOnly
        button.bezelStyle = .texturedRounded
        button.controlSize = .small
        button.target = self; button.action = action
        button.setAccessibilityLabel(label)
        button.setAccessibilityIdentifier(identifier.rawValue)
        button.toolTip = label + (label == "Back" ? " (⌘[)" : " (⌘])")
        button.sizeToFit()
        let item = NSToolbarItem(itemIdentifier: identifier)
        item.label = label; item.paletteLabel = label; item.toolTip = button.toolTip
        item.view = button
        // Manual health/KVO validation owns both the item and its custom button.
        item.autovalidates = false
        items[identifier] = item
    }

    func toolbarAllowedItemIdentifiers(_ toolbar: NSToolbar) -> [NSToolbarItem.Identifier] { [backID, forwardID] }
    func toolbarDefaultItemIdentifiers(_ toolbar: NSToolbar) -> [NSToolbarItem.Identifier] { [backID, forwardID] }
    func toolbar(_ toolbar: NSToolbar, itemForItemIdentifier identifier: NSToolbarItem.Identifier,
                 willBeInsertedIntoToolbar flag: Bool) -> NSToolbarItem? { items[identifier] }

    private var canNavigate: Bool {
        guard available, let webView, !webView.isHidden, !webView.isLoading,
              let url = webView.url, isLocalURL(url) else { return false }
        return true
    }
    var canGoBack: Bool {
        canNavigate && webView?.canGoBack == true && webView?.backForwardList.backItem.map { isLocalURL($0.url) } == true
    }
    var canGoForward: Bool {
        canNavigate && webView?.canGoForward == true && webView?.backForwardList.forwardItem.map { isLocalURL($0.url) } == true
    }
    func setAvailable(_ value: Bool) { available = value; refresh() }
    @objc func back() { if canGoBack { webView?.goBack() } }
    @objc func forward() { if canGoForward { webView?.goForward() } }

    private func refresh() {
        if let url = webView?.url, isLocalURL(url), url != lastURL {
            lastURL = url
            onLocalURLChange?(url)
        }
        backButton.isEnabled = canGoBack; items[backID]?.isEnabled = canGoBack
        forwardButton.isEnabled = canGoForward; items[forwardID]?.isEnabled = canGoForward
        webView?.allowsBackForwardNavigationGestures = canNavigate
    }

    /// The shell replaces all setup scripts on restart. Reinstall this independent, origin-bound bridge too.
    func installScript(port: Int) {
        let source = """
        (() => {
          if (location.origin !== "http://127.0.0.1:\(port)") return;
          const send = () => {
            const theme = document.documentElement.dataset.loonTheme;
            if (theme === "light" || theme === "dark")
              window.webkit.messageHandlers.windowAppearance.postMessage(theme);
          };
          new MutationObserver(send).observe(document.documentElement, {
            attributes: true, attributeFilter: ['data-loon-theme']
          });
          send();
        })();
        """
        webView?.configuration.userContentController.addUserScript(
            WKUserScript(source: source, injectionTime: .atDocumentEnd, forMainFrameOnly: true, in: .defaultClient))
    }

    func userContentController(_ userContentController: WKUserContentController, didReceive message: WKScriptMessage) {
        guard message.webView === webView, message.frameInfo.isMainFrame,
              let frameURL = message.frameInfo.request.url, isLocalURL(frameURL),
              let currentURL = webView?.url, isLocalURL(currentURL),
              let theme = message.body as? String, theme == "light" || theme == "dark" else { return }
        window?.appearance = NSAppearance(named: theme == "dark" ? .darkAqua : .aqua)
    }
}
