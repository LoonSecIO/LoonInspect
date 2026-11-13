import AppKit

@MainActor
private final class GuideDocumentView: NSView {
    override var isFlipped: Bool { true }
}

/// A local explanation of the Mac installation's operating and data boundaries.
@MainActor
final class MacGuideWindow: NSWindowController {
    init() {
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 620, height: 650),
                              styleMask: [.titled, .closable, .resizable], backing: .buffered, defer: false)
        window.title = "LoonInspect on this Mac"
        window.contentMinSize = NSSize(width: 500, height: 420)
        window.isReleasedWhenClosed = false
        window.setFrameAutosaveName("LoonInspectMacGuide")
        window.center()
        super.init(window: window)

        let scroll = NSScrollView()
        scroll.hasVerticalScroller = true
        scroll.autohidesScrollers = true
        scroll.drawsBackground = true
        scroll.backgroundColor = .windowBackgroundColor
        window.contentView = scroll
        let document = GuideDocumentView()
        document.translatesAutoresizingMaskIntoConstraints = false
        scroll.documentView = document
        let stack = NSStackView()
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 18
        stack.translatesAutoresizingMaskIntoConstraints = false
        document.addSubview(stack)

        func text(_ value: String, font: NSFont, color: NSColor = .labelColor) -> NSTextField {
            let field = NSTextField(wrappingLabelWithString: value)
            field.font = font
            field.textColor = color
            field.isSelectable = true
            return field
        }
        let title = text("Your local LoonInspect installation", font: .systemFont(ofSize: 23, weight: .semibold))
        stack.addArrangedSubview(title)
        let version = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "Development"
        let build = Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "unstamped"
        stack.addArrangedSubview(text("Version \(version) · Build \(build)", font: .systemFont(ofSize: 12), color: .secondaryLabelColor))

        let sections = [
            ("Runs on this Mac", "The app includes its web interface, application services, and PostgreSQL. The interface is available on this Mac only. No Docker or separate database installation is needed."),
            ("Connections and sharing", "Configured connections contact Jamf Pro and delivery destinations. Community sharing is preselected during setup; review that choice and Settings → Data Sharing before collecting production inventory. Configured integrations, sharing, and AI can send data outside this Mac."),
            ("Closing, quitting, and sleep", "Closing the window leaves LoonInspect running. Quit stops its local services. Collection pauses while this Mac sleeps or the app is quit. Use a reachable server deployment for incoming Jamf webhooks and continuous collection."),
            ("Your data and credentials", "The database and logs live in your user’s Application Support folder. Stored connection secrets are encrypted using a key in login Keychain; the inventory database itself is unencrypted. Software running as the same macOS user can access the local instance’s files and keys."),
            ("Installing, moving, and updating", "Copying the installer to another Apple silicon Mac creates a separate installation; it does not move existing accounts, connections, or data. To update, quit LoonInspect and replace the app with the new notarized version. There is no automatic updater. See the Mac app guide for backup and restore instructions."),
        ]
        for (heading, body) in sections {
            let group = NSStackView(views: [
                text(heading, font: .systemFont(ofSize: 14, weight: .semibold)),
                text(body, font: .systemFont(ofSize: 13), color: .secondaryLabelColor),
            ])
            group.orientation = .vertical
            group.alignment = .leading
            group.spacing = 5
            stack.addArrangedSubview(group)
            group.widthAnchor.constraint(equalTo: stack.widthAnchor).isActive = true
            group.arrangedSubviews.forEach { $0.widthAnchor.constraint(equalTo: group.widthAnchor).isActive = true }
        }
        let guide = NSButton(title: "Mac App Guide ↗", target: self, action: #selector(openGuide))
        let source = NSButton(title: "Source Repository ↗", target: self, action: #selector(openSource))
        guide.setAccessibilityLabel("Open Mac app guide in browser")
        source.setAccessibilityLabel("Open source repository in browser")
        [guide, source].forEach { $0.bezelStyle = .rounded }
        let links = NSStackView(views: [guide, source])
        links.orientation = .horizontal
        links.spacing = 12
        stack.addArrangedSubview(links)
        NSLayoutConstraint.activate([
            document.widthAnchor.constraint(equalTo: scroll.contentView.widthAnchor),
            stack.leadingAnchor.constraint(equalTo: document.leadingAnchor, constant: 26),
            stack.trailingAnchor.constraint(equalTo: document.trailingAnchor, constant: -26),
            stack.topAnchor.constraint(equalTo: document.topAnchor, constant: 26),
            stack.bottomAnchor.constraint(equalTo: document.bottomAnchor, constant: -26),
            title.widthAnchor.constraint(equalTo: stack.widthAnchor),
        ])
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) is unavailable") }
    func show() {
        window?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }
    @objc private func openGuide() {
        NSWorkspace.shared.open(URL(string: "https://github.com/LoonSecIO/LoonInspect/blob/main/docs/macos-app.md")!)
    }
    @objc private func openSource() {
        NSWorkspace.shared.open(URL(string: "https://github.com/LoonSecIO/LoonInspect")!)
    }
}
