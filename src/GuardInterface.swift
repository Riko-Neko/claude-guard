import AppKit
import WebKit

struct GuardPageLocation {
    let directory: URL
    let page: URL
    init(resources: URL) {
        directory = resources.appendingPathComponent("Interface", isDirectory: true)
        page = directory.appendingPathComponent("index.html", isDirectory: false)
    }
}

enum GuardSetupPolicy {
    static func requiresFilterShutdown(currentMode: String, configured: Bool, targetMode: String) -> Bool {
        return configured && currentMode == "enhanced" && targetMode == "proxy"
    }
}

enum GuardChildEnvironment {
    static func make(_ source: [String:String], language: String) -> [String:String] {
        var result = source.filter { !$0.key.hasPrefix("SUDO_") }
        result["CLAUDE_GUARD_LANGUAGE"] = language
        return result
    }
}

enum GuardLifecyclePolicy {
    // A pending setup or connection check is not evidence Claude is running.
    static func decision(setup: Bool, operation: Bool, backend: Bool, claude: Bool) -> String {
        if operation { return "operation" }
        if setup { return "cancelSetup" }
        if claude { return "claude" }
        if backend { return "endCheck" }
        return "continue"
    }
}

final class GuardInterface: NSObject, WKScriptMessageHandler, WKNavigationDelegate, NSWindowDelegate {
    var onAction: (([String: Any]) -> Void)?
    var state: (() -> [String: Any])?
    private var window: NSWindow?
    private var settingsWeb: WKWebView?
    private var menuWeb: WKWebView?
    private var settingsReady = false
    private var waitingEvents = [[String: Any]]()
    private let popover = NSPopover()
    private var criticalPanel: NSPanel?
    private var criticalTitle: NSTextField?
    private var criticalBody: NSTextField?
    private var criticalTimer: Timer?
    private var notice = GuardNoticePresentation()
    weak var noticeAnchor: NSStatusBarButton?
    private var tables = [String: [String: String]]()
    private var previewLanguage: String? = ProcessInfo.processInfo.arguments.contains("--preview-ui") ? "zh-Hant" : nil
    var language: String {
        get { previewLanguage ?? UserDefaults.standard.string(forKey: "GuardLanguage") ?? "zh-Hant" }
        set { if ["zh-Hant", "zh-Hans", "en"].contains(newValue) {
            if previewLanguage != nil { previewLanguage = newValue }
            else { UserDefaults.standard.set(newValue, forKey: "GuardLanguage") }
        } }
    }
    var visible: Bool { window?.isVisible == true }

    override init() {
        super.init()
        if let url = Bundle.main.resourceURL?.appendingPathComponent("Interface/strings.json"),
           let data = try? Data(contentsOf: url),
           let tables = try? JSONDecoder().decode([String: [String: String]].self, from: data) { self.tables = tables }
        popover.behavior = .transient
        popover.contentSize = NSSize(width: 350, height: 365)
    }
    func tr(_ text: String) -> String {
        if let translated = tables[language]?[text] { return translated }
        if language == "zh-Hant" { return text.applyingTransform(StringTransform("Hans-Hant"), reverse: false) ?? text }
        return text
    }
    private func makeWeb(_ view: String) -> WKWebView {
        let config = WKWebViewConfiguration()
        config.userContentController.add(self, name: "guard")
        // loadFileURL requires an unadorned local file URL. Pass the view mode
        // at document start rather than putting a query on the file URL.
        let mode = view == "menu" ? "menu" : "setup"
        config.userContentController.addUserScript(WKUserScript(
            source: "window.GUARD_VIEW = '\(mode)';", injectionTime: .atDocumentStart, forMainFrameOnly: true))
        let web = WKWebView(frame: .zero, configuration: config)
        web.navigationDelegate = self
        web.setValue(false, forKey: "drawsBackground")
        if let resources = Bundle.main.resourceURL {
            let location = GuardPageLocation(resources: resources)
            web.loadFileURL(location.page, allowingReadAccessTo: location.directory)
        }
        return web
    }
    func showSettings() {
        popover.close()
        if window == nil {
            let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 720, height: 740),
                                  styleMask: [.titled, .closable, .miniaturizable], backing: .buffered, defer: false)
            window.title = "Claude Guard"
            window.isReleasedWhenClosed = false
            window.backgroundColor = NSColor(calibratedRed: 0.965, green: 0.953, blue: 0.933, alpha: 1)
            let web = makeWeb("setup")
            window.contentView = web
            self.window = window; self.settingsWeb = web
            window.center()
        }
        window?.makeKeyAndOrderFront(nil)
        emit(["kind":"settingsOpened"])
        emit(currentState())
        NSApp.activate(ignoringOtherApps: true)
    }
    func closeSettings() { window?.close() }
    func toggleMenu(relativeTo button: NSStatusBarButton) {
        if popover.isShown { popover.close(); return }
        if menuWeb == nil {
            let controller = NSViewController()
            let web = makeWeb("menu")
            controller.view = web
            popover.contentViewController = controller
            menuWeb = web
        }
        refreshMenu()
        popover.show(relativeTo: button.bounds, of: button, preferredEdge: .minY)
    }
    func closeMenu() { popover.close() }

    func showCriticalAlert(title: String, body: String) {
        criticalTimer?.invalidate(); criticalTimer = nil
        notice.show()
        if criticalPanel == nil {
            let panel = NSPanel(contentRect: NSRect(x: 0, y: 0, width: 360, height: 240),
                                styleMask: [.titled, .closable, .nonactivatingPanel], backing: .buffered, defer: false)
            panel.title = "Claude Guard"
            panel.isReleasedWhenClosed = false
            panel.level = .floating
            panel.hidesOnDeactivate = false
            panel.becomesKeyOnlyIfNeeded = true
            panel.delegate = self
            panel.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary]
            let heading = NSTextField(wrappingLabelWithString: "")
            heading.font = .boldSystemFont(ofSize: 15)
            heading.textColor = NSColor(calibratedRed: 0.72, green: 0.38, blue: 0.27, alpha: 1)
            let details = NSTextField(wrappingLabelWithString: "")
            details.font = .systemFont(ofSize: 12)
            details.isSelectable = true
            let review = NSButton(title: tr("reviewConnection"), target: self, action: #selector(reviewCriticalAlert))
            review.bezelStyle = .rounded
            let dismiss = NSButton(title: tr("acknowledgeAlert"), target: self, action: #selector(dismissCriticalAlert))
            dismiss.bezelStyle = .rounded
            let buttons = NSStackView(views: [dismiss, review])
            buttons.orientation = .horizontal; buttons.alignment = .centerY; buttons.spacing = 12
            let stack = NSStackView(views: [heading, details, buttons])
            stack.orientation = .vertical; stack.alignment = .leading; stack.spacing = 12
            stack.translatesAutoresizingMaskIntoConstraints = false
            let view = panel.contentView!
            view.addSubview(stack)
            NSLayoutConstraint.activate([
                stack.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 16),
                stack.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -16),
                stack.topAnchor.constraint(equalTo: view.topAnchor, constant: 16),
                stack.bottomAnchor.constraint(lessThanOrEqualTo: view.bottomAnchor, constant: -16),
                heading.widthAnchor.constraint(equalTo: stack.widthAnchor),
                details.widthAnchor.constraint(equalTo: stack.widthAnchor)
            ])
            criticalPanel = panel; criticalTitle = heading; criticalBody = details
        }
        criticalTitle?.stringValue = title
        criticalTitle?.textColor = NSColor(calibratedRed: 0.72, green: 0.38, blue: 0.27, alpha: 1)
        criticalBody?.stringValue = body
        positionCriticalAlert()
        // A nonactivating menu-bar notice must not steal focus or raise the
        // configuration window while the user is working in another app.
        criticalPanel?.orderFrontRegardless()
    }
    private func positionCriticalAlert() {
        guard let panel = criticalPanel else { return }
        let rawAnchor = noticeAnchor.flatMap { button in
            button.window.map { $0.convertToScreen(button.convert(button.bounds, to: nil)) }
        }
        let anchor = rawAnchor.flatMap { $0.width > 0 && $0.height > 0 ? $0 : nil }
        let screen = anchor.flatMap { rect in NSScreen.screens.first { $0.frame.intersects(rect) } } ?? NSScreen.main
        guard let visible = screen?.visibleFrame else { return }
        panel.setFrameOrigin(GuardNoticePlacement.origin(anchor: anchor, visibleFrame: visible, size: panel.frame.size))
    }
    @discardableResult func showRecoveredNotice(title: String, body: String) -> Bool {
        guard criticalPanel?.isVisible == true, let token = notice.recover() else { return false }
        criticalTimer?.invalidate()
        criticalTitle?.stringValue = title
        criticalTitle?.textColor = .systemGreen
        criticalBody?.stringValue = body
        let timer = Timer(timeInterval: 1, repeats: false) { [weak self] _ in
            guard let self = self, self.notice.expire(token) else { return }
            self.criticalPanel?.close()
            self.criticalTimer = nil
        }
        criticalTimer = timer
        RunLoop.main.add(timer, forMode: .common)
        return true
    }
    func windowWillClose(_ notification: Notification) {
        guard let panel = notification.object as? NSPanel, panel === criticalPanel else { return }
        criticalTimer?.invalidate(); criticalTimer = nil
        notice.dismiss()
    }
    @objc private func dismissCriticalAlert() { criticalPanel?.close() }
    @objc private func reviewCriticalAlert() {
        criticalPanel?.close()
        onAction?(["action": "settings"])
    }
    func clearCriticalAlert() {
        criticalTimer?.invalidate(); criticalTimer = nil
        notice.dismiss(); criticalPanel?.close()
    }
    private func send(_ value: [String: Any], to web: WKWebView?) {
        guard let web = web, let data = try? JSONSerialization.data(withJSONObject: value),
              let json = String(data: data, encoding: .utf8) else { return }
        web.evaluateJavaScript("window.guardEvent(\(json))", completionHandler: nil)
    }
    func emit(_ value: [String: Any]) {
        if settingsReady { send(value, to: settingsWeb) }
        else { waitingEvents.append(value) }
    }
    func refreshMenu() {
        let value = currentState()
        let state = value["state"] as? [String: Any] ?? [:]
        let hasNotice = !(state["connectionReason"] as? String ?? "").isEmpty
        popover.contentSize = NSSize(width: 350, height: hasNotice ? 540 : 365)
        send(value, to: menuWeb)
        if settingsReady { send(value, to: settingsWeb) }
    }
    func currentState() -> [String: Any] {
        var value = state?() ?? [:]
        value["language"] = language
        return ["kind": "state", "state": value]
    }
    func userContentController(_ userContentController: WKUserContentController, didReceive message: WKScriptMessage) {
        guard message.frameInfo.isMainFrame, message.frameInfo.request.url?.isFileURL == true,
              let body = message.body as? [String: Any] else { return }
        if body["action"] as? String == "ready" {
            send(currentState(), to: message.webView)
            if message.webView === settingsWeb {
                settingsReady = true
                for event in waitingEvents { send(event, to: settingsWeb) }
                waitingEvents.removeAll()
            }
        } else if body["action"] as? String == "language", let language = body["language"] as? String {
            self.language = language
            refreshMenu()
            onAction?(body)
        } else { onAction?(body) }
    }
    func webView(_ webView: WKWebView, decidePolicyFor navigationAction: WKNavigationAction,
                 decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        // All interface assets are bundled. This view never navigates to external sites.
        decisionHandler(navigationAction.request.url?.isFileURL == true ? .allow : .cancel)
    }
}
