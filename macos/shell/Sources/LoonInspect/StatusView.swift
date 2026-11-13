import AppKit

/// Native startup, shutdown, and recovery presentation above the app's web interface.
@MainActor
final class StatusView: NSView {
    var onReload: (() -> Void)?
    var onShowLogs: (() -> Void)?
    var onQuit: (() -> Void)?

    private let heading = NSTextField(wrappingLabelWithString: "")
    private let message = NSTextView()
    private let progress = NSProgressIndicator()
    private let reloadButton = NSButton(title: "Reload Window", target: nil, action: nil)
    private var detailsHeight: NSLayoutConstraint!

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        wantsLayer = true
        setAccessibilityRole(.group)
        setAccessibilityLabel("LoonInspect status")

        let icon = NSImageView()
        icon.image = NSApp.applicationIconImage
        icon.imageScaling = .scaleProportionallyUpOrDown
        icon.setAccessibilityElement(false)
        heading.font = .systemFont(ofSize: 25, weight: .semibold)
        heading.textColor = .labelColor
        heading.alignment = .center
        heading.isSelectable = true

        message.isEditable = false
        message.isSelectable = true
        message.drawsBackground = false
        message.font = .systemFont(ofSize: 14)
        message.textColor = .secondaryLabelColor
        message.textContainerInset = NSSize(width: 6, height: 6)
        message.textContainer?.lineFragmentPadding = 0
        message.textContainer?.widthTracksTextView = true
        message.isHorizontallyResizable = false
        message.isVerticallyResizable = true
        message.frame = NSRect(x: 0, y: 0, width: 600, height: 152)
        message.minSize = NSSize(width: 0, height: 152)
        message.maxSize = NSSize(width: CGFloat.greatestFiniteMagnitude, height: CGFloat.greatestFiniteMagnitude)
        message.textContainer?.containerSize = NSSize(width: 600, height: CGFloat.greatestFiniteMagnitude)
        message.autoresizingMask = .width
        message.setAccessibilityLabel("Status details")
        let details = NSScrollView()
        details.drawsBackground = false
        details.hasVerticalScroller = true
        details.autohidesScrollers = true
        details.documentView = message
        detailsHeight = details.heightAnchor.constraint(equalToConstant: 80)

        progress.style = .spinning
        progress.controlSize = .regular
        progress.isIndeterminate = true
        progress.setAccessibilityLabel("LoonInspect is working")
        reloadButton.target = self
        reloadButton.action = #selector(reload)
        let logs = NSButton(title: "Show Logs", target: self, action: #selector(showLogs))
        let quit = NSButton(title: "Quit", target: self, action: #selector(quitApp))
        [reloadButton, logs, quit].forEach { $0.bezelStyle = .rounded }
        let buttons = NSStackView(views: [reloadButton, logs, quit])
        buttons.orientation = .horizontal
        buttons.spacing = 12

        let stack = NSStackView(views: [icon, heading, progress, details, buttons])
        stack.orientation = .vertical
        stack.alignment = .centerX
        stack.spacing = 18
        stack.translatesAutoresizingMaskIntoConstraints = false
        addSubview(stack)
        NSLayoutConstraint.activate([
            stack.centerXAnchor.constraint(equalTo: centerXAnchor),
            stack.centerYAnchor.constraint(equalTo: centerYAnchor),
            stack.leadingAnchor.constraint(greaterThanOrEqualTo: leadingAnchor, constant: 32),
            stack.trailingAnchor.constraint(lessThanOrEqualTo: trailingAnchor, constant: -32),
            stack.widthAnchor.constraint(lessThanOrEqualToConstant: 600),
            stack.topAnchor.constraint(greaterThanOrEqualTo: topAnchor, constant: 24),
            icon.widthAnchor.constraint(equalToConstant: 76),
            icon.heightAnchor.constraint(equalToConstant: 76),
            heading.widthAnchor.constraint(equalTo: stack.widthAnchor),
            details.widthAnchor.constraint(equalTo: stack.widthAnchor),
            detailsHeight,
            progress.widthAnchor.constraint(equalToConstant: 24),
            progress.heightAnchor.constraint(equalToConstant: 24),
        ])
        let preferredWidth = stack.widthAnchor.constraint(equalToConstant: 600)
        preferredWidth.priority = .defaultHigh
        preferredWidth.isActive = true
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) is unavailable") }

    override func draw(_ dirtyRect: NSRect) {
        NSColor.windowBackgroundColor.setFill()
        dirtyRect.fill()
        super.draw(dirtyRect)
    }

    func update(title: String, message: String, busy: Bool, canReload: Bool = false) {
        heading.stringValue = title
        self.message.string = message
        self.message.alignment = busy ? .center : .left
        let measured = (message as NSString).boundingRect(
            with: NSSize(width: min(588, max(200, bounds.width - 76)), height: .greatestFiniteMagnitude),
            options: [.usesLineFragmentOrigin, .usesFontLeading], attributes: [.font: NSFont.systemFont(ofSize: 14)])
        detailsHeight.constant = min(180, max(64, ceil(measured.height) + 20))
        self.message.minSize.height = detailsHeight.constant
        self.message.scrollToBeginningOfDocument(nil)
        progress.isHidden = !busy
        if busy { progress.startAnimation(nil) } else { progress.stopAnimation(nil) }
        reloadButton.isHidden = !canReload
        NSAccessibility.post(element: heading, notification: .valueChanged)
    }

    @objc private func reload() { onReload?() }
    @objc private func showLogs() { onShowLogs?() }
    @objc private func quitApp() { onQuit?() }
}
