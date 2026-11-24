import AppKit
import WebKit

/// Exercises real native menus, controls and WebKit finding against synthetic page content.
@MainActor
enum FindHarness {
    static func views(_ view: NSView) -> [NSView] { [view] + view.subviews.flatMap(views) }
    static func check(_ value: Bool, _ message: String) throws {
        if !value { throw HarnessFailure.failed(message) }
    }
    static func wait(_ message: String, _ condition: @escaping () -> Bool) async throws {
        let deadline = Date().addingTimeInterval(8)
        while !condition() {
            if Date() > deadline { throw HarnessFailure.failed("Timed out: \(message)") }
            try await Task.sleep(for: .milliseconds(25))
        }
    }
    static func run(delegate: AppDelegate, web: WKWebView) async throws {
        let window = web.window!
        let content = window.contentView!
        let all = views(content)
        let field = all.compactMap { $0 as? NSSearchField }.first!
        let status = all.compactMap { $0 as? NSTextField }.first { $0.accessibilityIdentifier() == "page-find-status" }!
        let done = all.compactMap { $0 as? NSButton }.first { $0.accessibilityIdentifier() == "page-find-close" }!
        let matchCase = all.compactMap { $0 as? NSButton }.first { $0.title == "Match case" }!
        let pageSearch = all.compactMap { $0 as? NSButton }.first { $0.title == "Go to page search" }!
        let aiSearch = all.compactMap { $0 as? NSButton }.first { $0.title == "Go to AI search" }!
        let edit = NSApp.mainMenu!.items.first { $0.submenu?.title == "Edit" }!.submenu!
        let menu = edit.items.first { $0.submenu?.title == "Find" }!.submenu!
        let open = menu.items.first { $0.keyEquivalent == "f" }!
        try check(open.keyEquivalentModifierMask == .command && delegate.validateMenuItem(open), "Cmd-F is not available on a healthy page")
        func action(_ name: String) throws {
            guard let item = menu.items.first(where: { $0.title == name }), let selector = item.action else {
                throw HarnessFailure.failed("Missing Find menu item: \(name)")
            }
            try check(delegate.validateMenuItem(item), "Find action disabled: \(name)")
            NSApp.sendAction(selector, to: delegate, from: item)
        }
        func enter(_ text: String) {
            field.stringValue = text
            field.delegate?.controlTextDidChange?(Notification(name: NSControl.textDidChangeNotification, object: field))
        }
        func found(_ text: String) async throws {
            enter(text)
            try await wait("finding \(text)") { status.stringValue.hasPrefix("Match found.") }
        }
        func missing(_ text: String) async throws {
            enter(text)
            try await wait("no match for \(text)") { status.stringValue.hasPrefix("No matches on this page.") }
        }
        func selected() async throws -> String {
            try await web.evaluateJavaScript("window.getSelection()?.anchorNode?.parentElement?.closest('p')?.id || ''") as? String ?? ""
        }

        window.makeKeyAndOrderFront(nil)
        let previousDelegate = NSApp.delegate
        NSApp.delegate = delegate
        let key = NSEvent.keyEvent(with: .keyDown, location: .zero, modifierFlags: .command,
                                  timestamp: 0, windowNumber: window.windowNumber, context: nil,
                                  characters: "f", charactersIgnoringModifiers: "f", isARepeat: false, keyCode: 3)!
        let handled = NSApp.mainMenu!.performKeyEquivalent(with: key)
        NSApp.delegate = previousDelegate
        try check(handled, "The actual Cmd-F key equivalent did not dispatch")
        try await wait("Find opens and focuses its search field") { !field.isHiddenOrHasHiddenAncestor && field.currentEditor() != nil }
        try await found("Needle")
        print("PASS: native Cmd-F menu opens a focused Find bar and WebKit finds page text")
        let first = try await selected()
        try action("Find Next")
        try await Task.sleep(for: .milliseconds(150))
        let second = try await selected()
        try check(first != second && !first.isEmpty && !second.isEmpty, "Find Next did not select a different rendered occurrence")
        try action("Find Previous")
        try await Task.sleep(for: .milliseconds(150))
        try check(try await selected() == first, "Find Previous did not return to the previous occurrence")
        for _ in 0..<3 { try action("Find Next"); try await Task.sleep(for: .milliseconds(100)) }
        try check(try await selected() == first, "Finding did not wrap across three occurrences")
        print("PASS: next, previous, and wrap select the expected rendered occurrences")

        matchCase.performClick(nil)
        try await missing("NEEDLE")
        matchCase.performClick(nil)
        try await found("NEEDLE")
        print("PASS: case-sensitive and insensitive matching differ as requested")

        try await found("Across inline elements")
        try check(try await selected() == "split", "Text across inline elements was not selected")
        try await found("Café")
        try await found("日本語")
        try await found("🔎")
        print("PASS: inline markup, accented text, non-Latin text and emoji remain searchable")
        try await missing("invisible-fixture-content")
        try await missing("password-fixture-content")
        try await missing("not-on-this-page")
        try await missing("'); window.submissions = 77; //")
        try check((try await web.evaluateJavaScript("window.submissions")) as? Int == 0, "Find interpreted query text as script")
        print("PASS: hidden content and password values are excluded; no-match feedback names page scope")

        try await found("last occurrence")
        try check((try await web.evaluateJavaScript("window.scrollY > 0")) as? Bool == true, "Offscreen match was not scrolled into view")
        // Reopening Find focuses/selects the retained query. It must not advance to another occurrence.
        try action("Find in Page…")
        try check(field.currentEditor()?.selectedRange.length == field.stringValue.utf16.count, "Repeated Cmd-F did not select the query")
        try check(web.frame.height > 250 && field.bounds.width >= 200, "Find bar collapsed the page or its own query field")
        print("PASS: offscreen matches scroll into view; repeated Cmd-F selects the query without collapsing the page")

        enter("Needle")
        enter("superseded-query-with-no-match")
        try await wait("latest query wins") { status.stringValue.hasPrefix("No matches on this page.") }
        try await Task.sleep(for: .milliseconds(250))
        try check(status.stringValue.hasPrefix("No matches"), "An old result replaced the latest query")
        enter("")
        try await wait("clearing the query restores the empty state") { status.stringValue == "Type to find text on this page." }
        print("PASS: rapid edits keep the newest result and clearing the query resets the controls")

        // Use Selection captures only the explicit page selection and never submits it to a provider.
        _ = try await web.evaluateJavaScript("let r=document.createRange(); r.selectNodeContents(document.getElementById('unicode')); getSelection().removeAllRanges(); getSelection().addRange(r)")
        try action("Use Selection for Find")
        try await wait("selected text seeds Find") { field.stringValue == "Café Straße 日本語 🔎" }
        try await wait("selected text is found") { status.stringValue.hasPrefix("Match found.") }
        done.performClick(nil)
        try check(field.isHiddenOrHasHiddenAncestor, "Done left the find bar visible")
        try action("Find Next")
        try await wait("Find Next reopens the retained query") { !field.isHiddenOrHasHiddenAncestor && status.stringValue.hasPrefix("Match found.") }
        try action("Find in Page…")
        guard let editor = field.currentEditor() as? NSTextView else { throw HarnessFailure.failed("No field editor for Escape") }
        editor.doCommand(by: #selector(NSResponder.cancelOperation(_:)))
        try check(field.isHiddenOrHasHiddenAncestor && window.firstResponder !== editor, "Escape did not close Find and restore focus")
        print("PASS: selected-text search, Done, retained-query reopening, and Escape restore usable focus")

        try action("Find in Page…")
        try await wait("page and AI actions discovered") { !pageSearch.isHidden && !aiSearch.isHidden }
        enter("local find query")
        pageSearch.performClick(nil)
        try await wait("page search action closes find") { field.isHiddenOrHasHiddenAncestor }
        try check((try await web.evaluateJavaScript("document.activeElement.id")) as? String == "page-query", "Page-search action did not focus the page's control")
        try check((try await web.evaluateJavaScript("document.getElementById('page-query').value")) as? String == "retained filter", "Find overwrote a saved page filter")
        try check((try await web.evaluateJavaScript("window.submissions")) as? Int == 0, "Focusing page search submitted a query")
        print("PASS: page-search handoff focuses existing filters without changing or submitting them")

        try action("Find in Page…")
        try await wait("AI action available") { !aiSearch.isHidden }
        aiSearch.performClick(nil)
        try await wait("AI action closes find") { field.isHiddenOrHasHiddenAncestor }
        try await Task.sleep(for: .milliseconds(100))
        try check((try await web.evaluateJavaScript("document.getElementById('ai-toggle').checked")) as? Bool == true, "Explicit AI action did not choose the existing AI mode")
        try check((try await web.evaluateJavaScript("document.activeElement.matches('[data-page-ai-search]')")) as? Bool == true, "AI action did not focus the existing prompt")
        try check((try await web.evaluateJavaScript("window.submissions")) as? Int == 0, "AI handoff sent a question without submission")
        print("PASS: explicit AI handoff uses the existing gated control and never submits a question")

        try action("Find in Page…")
        try await wait("AI bar is ready") { !field.isHiddenOrHasHiddenAncestor }
        _ = try await web.evaluateJavaScript("document.getElementById('ai-toggle').remove(); document.getElementById('page-query').removeAttribute('data-page-ai-search')")
        try await wait("AI action disappears when the page removes availability") { aiSearch.isHidden }
        print("PASS: AI-disabled or removed page controls remove the AI action")

        try await missing("newly loaded result")
        _ = try await web.evaluateJavaScript("document.getElementById('dynamic').textContent='newly loaded result'")
        try await wait("a stale negative result is invalidated") { status.stringValue.hasPrefix("Page content changed.") }
        try action("Find Next")
        try await wait("updated content can be found") { status.stringValue.hasPrefix("Match found.") }
        print("PASS: dynamic content invalidates stale feedback and the next search reads the updated page")

        _ = try await web.evaluateJavaScript("history.pushState({}, '', '/fixture-next-page'); document.getElementById('dynamic').textContent='replacement page'")
        try await wait("route changes recheck the retained query") { status.stringValue.hasPrefix("No matches on this page.") }
        // Replay a delayed notification for the DOM that the route search already searched.
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            web.evaluateJavaScript("window.webkit.messageHandlers.pageFind.postMessage('changed'); true", in: nil, in: .defaultClient) { result in
                continuation.resume(with: result.map { _ in () })
            }
        }
        try await Task.sleep(for: .milliseconds(250))
        try check(status.stringValue.hasPrefix("No matches on this page."), "A delayed notification invalidated a result for unchanged content")
        _ = try await web.evaluateJavaScript("document.getElementById('dynamic').textContent='newly loaded result'")
        try await wait("a later mutation still invalidates the route result") { status.stringValue.hasPrefix("Page content changed.") }
        try action("Find Next")
        try await wait("the later revision is searchable") { status.stringValue.hasPrefix("Match found.") }
        print("PASS: route searches ignore delayed notifications for searched content and still invalidate later mutations")

        _ = try await web.evaluateJavaScript("document.getElementById('page-query').setAttribute('data-page-search','')")
        try await wait("page-search control is offered again") { !pageSearch.isHidden }
        _ = try await web.evaluateJavaScript("document.getElementById('page-query').disabled=true")
        pageSearch.performClick(nil)
        try await wait("disappearing control is diagnosed") { status.stringValue.hasPrefix("That search control is no longer available.") }
        try check(!field.isHiddenOrHasHiddenAncestor, "A refused handoff stranded focus outside Find")
        print("PASS: a control disabled during handoff explains what happened and how to retry")

        let oldPage = try await web.evaluateJavaScript("document.body.dataset.request") as? String
        let update = NSApp.mainMenu!.items.first!.submenu!.items.first { $0.title == "Check for Updates Daily" }!
        NSApp.sendAction(update.action!, to: delegate, from: update)
        try await wait("service restart finishes") { !web.isHidden && !web.isLoading }
        let deadline = Date().addingTimeInterval(8)
        while (try? await web.evaluateJavaScript("document.body.dataset.request") as? String) == oldPage {
            if Date() > deadline { throw HarnessFailure.failed("Restart did not reload the fixture") }
            try await Task.sleep(for: .milliseconds(25))
        }
        try action("Find in Page…")
        try await wait("the Find bridge survives service restart") { !pageSearch.isHidden && !aiSearch.isHidden }
        try await found("Needle")
        print("PASS: native finding and page/AI discovery work after a local-service restart")

        window.setContentSize(NSSize(width: 760, height: 560))
        content.layoutSubtreeIfNeeded()
        try check(field.bounds.width >= 200 && web.frame.height > 250, "Find is unusable at the app's minimum window size")
        if let path = ProcessInfo.processInfo.environment["LOONINSPECT_TEST_SCREENSHOT"],
           let bitmap = content.bitmapImageRepForCachingDisplay(in: content.bounds) {
            content.cacheDisplay(in: content.bounds, to: bitmap)
            try bitmap.representation(using: .png, properties: [:])?.write(to: URL(fileURLWithPath: path))
        }
        done.performClick(nil)
        print("PASS: Find remains usable at the minimum Mac window size")
    }
}
