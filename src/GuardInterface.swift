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
    private var criticalTechnical: NSTextField?
    private var criticalTechnicalScroll: NSScrollView?
    private var criticalTechnicalHeight: NSLayoutConstraint?
    private var criticalIcon: NSImageView?
    private var criticalButtons: NSStackView?
    private var criticalHeights: [ObjectIdentifier:NSLayoutConstraint] = [:]
    private var criticalRisk: NSTextField?
    private var criticalApprove: NSButton?
    private var criticalReview: NSButton?
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
    var menuVisible: Bool { popover.isShown }

    override init() {
        super.init()
        if let url = Bundle.main.resourceURL?.appendingPathComponent("Interface/strings.json"),
           let data = try? Data(contentsOf: url),
           let tables = try? JSONDecoder().decode([String: [String: String]].self, from: data) { self.tables = tables }
        popover.behavior = .transient
        popover.contentSize = NSSize(width: 360, height: 600)
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

    func showCriticalAlert(title: String, body: String, diagnostic: [String:Any]? = nil) {
        prepareCriticalAlert(title: title, body: body, diagnostic: diagnostic)
        criticalPanel?.orderFrontRegardless()
    }
    func prepareCriticalAlert(title: String, body: String, diagnostic: [String:Any]? = nil) {
        criticalTimer?.invalidate(); criticalTimer = nil
        notice.show()
        let accent = NSColor(calibratedRed: 0.73, green: 0.38, blue: 0.27, alpha: 1)
        if criticalPanel == nil {
            let panel = NSPanel(contentRect: NSRect(x: 0, y: 0, width: 340, height: 120),
                                styleMask: [.borderless, .nonactivatingPanel], backing: .buffered, defer: false)
            panel.isReleasedWhenClosed = false; panel.hasShadow = true
            panel.isOpaque = false; panel.backgroundColor = .clear
            panel.level = .floating; panel.hidesOnDeactivate = false
            panel.becomesKeyOnlyIfNeeded = true; panel.delegate = self
            panel.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary]
            let surface = NSVisualEffectView()
            surface.material = .popover; surface.blendingMode = .behindWindow; surface.state = .active
            surface.wantsLayer = true; surface.layer?.cornerRadius = 12
            surface.layer?.borderWidth = 1; surface.layer?.borderColor = NSColor.separatorColor.cgColor
            panel.contentView = surface
            let icon = NSImageView(image: NSImage(systemSymbolName: "exclamationmark.shield.fill", accessibilityDescription: nil)!)
            icon.contentTintColor = accent
            let heading = NSTextField(wrappingLabelWithString: "")
            heading.font = .systemFont(ofSize: 16, weight: .semibold); heading.textColor = accent
            let close = NSButton(image: NSImage(systemSymbolName: "xmark", accessibilityDescription: tr("acknowledgeAlert"))!, target: self, action: #selector(dismissCriticalAlert))
            close.isBordered = false; close.contentTintColor = .secondaryLabelColor
            close.toolTip = tr("acknowledgeAlert")
            let header = NSStackView(views: [icon, heading, close])
            header.orientation = .horizontal; header.alignment = .centerY; header.spacing = 6
            let details = NSTextField(wrappingLabelWithString: "")
            details.font = .systemFont(ofSize: 14); details.isSelectable = true
            let technical = NSTextField(wrappingLabelWithString: "")
            technical.font = .monospacedSystemFont(ofSize: 12, weight: .regular)
            technical.textColor = .secondaryLabelColor; technical.isSelectable = true
            let technicalScroll = NSScrollView()
            technicalScroll.drawsBackground = false; technicalScroll.borderType = .noBorder
            technicalScroll.hasVerticalScroller = true; technicalScroll.autohidesScrollers = true
            technicalScroll.documentView = technical
            let risk = NSTextField(wrappingLabelWithString: "")
            risk.font = .systemFont(ofSize: 13)
            let review = NSButton(title: tr("reviewConnection"), target: self, action: #selector(reviewCriticalAlert))
            let approve = NSButton(title: tr("approveExitAction"), target: self, action: #selector(approveCriticalExit))
            let dismiss = NSButton(title: tr("acknowledgeAlert"), target: self, action: #selector(dismissCriticalAlert))
            for button in [dismiss, review, approve] {
                button.bezelStyle = .rounded; button.controlSize = .small
                button.font = .systemFont(ofSize: 12, weight: .medium)
            }
            approve.bezelColor = accent; approve.contentTintColor = .white
            let buttons = NSStackView(views: [dismiss, review, approve])
            buttons.orientation = .horizontal; buttons.alignment = .centerY
            buttons.distribution = .fillEqually; buttons.spacing = 6
            let stack = NSStackView(views: [header, details, technicalScroll, risk, buttons])
            stack.orientation = .vertical; stack.alignment = .leading; stack.spacing = 6
            stack.translatesAutoresizingMaskIntoConstraints = false
            surface.addSubview(stack)
            NSLayoutConstraint.activate([
                stack.leadingAnchor.constraint(equalTo: surface.leadingAnchor, constant: 10),
                stack.trailingAnchor.constraint(equalTo: surface.trailingAnchor, constant: -10),
                stack.topAnchor.constraint(equalTo: surface.topAnchor, constant: 10),
                stack.bottomAnchor.constraint(equalTo: surface.bottomAnchor, constant: -10),
                header.widthAnchor.constraint(equalTo: stack.widthAnchor),
                heading.widthAnchor.constraint(equalTo: stack.widthAnchor, constant: -50),
                icon.widthAnchor.constraint(equalToConstant: 20), icon.heightAnchor.constraint(equalToConstant: 21),
                close.widthAnchor.constraint(equalToConstant: 18), close.heightAnchor.constraint(equalToConstant: 18),
                details.widthAnchor.constraint(equalTo: stack.widthAnchor),
                technicalScroll.widthAnchor.constraint(equalTo: stack.widthAnchor),
                risk.widthAnchor.constraint(equalTo: stack.widthAnchor),
                buttons.widthAnchor.constraint(equalTo: stack.widthAnchor), buttons.heightAnchor.constraint(equalToConstant: 24)
            ])
            let technicalHeight = technicalScroll.heightAnchor.constraint(equalToConstant: 18)
            technicalHeight.isActive = true
            criticalTechnicalScroll = technicalScroll; criticalTechnicalHeight = technicalHeight
            for field in [heading, details, risk] {
                let height = field.heightAnchor.constraint(equalToConstant: 20)
                height.isActive = true; criticalHeights[ObjectIdentifier(field)] = height
            }
            criticalPanel = panel; criticalTitle = heading; criticalBody = details
            criticalTechnical = technical; criticalIcon = icon; criticalButtons = buttons
            criticalRisk = risk; criticalApprove = approve; criticalReview = review
        }
        criticalTitle?.stringValue = title; criticalTitle?.textColor = accent
        criticalIcon?.image = NSImage(systemSymbolName: "exclamationmark.shield.fill", accessibilityDescription: nil)
        criticalIcon?.contentTintColor = accent
        criticalBody?.stringValue = body
        let stage = diagnostic?["stage"] as? String
        let technical = diagnostic.map(GuardFailureTechnical.text) ?? ""
        criticalTechnical?.stringValue = technical.isEmpty ? "" : (stage.map { tr("failureStage_" + $0) + "\n" } ?? "") + technical
        refreshCriticalDetails()
    }
    func updateCriticalFailure(body: String, diagnostic: [String:Any]?) {
        guard criticalPanel?.isVisible == true, !notice.recovered else { return }
        criticalBody?.stringValue = body
        let technical = diagnostic.map(GuardFailureTechnical.text) ?? ""
        let stage = diagnostic?["stage"] as? String
        criticalTechnical?.stringValue = technical.isEmpty ? "" : (stage.map { tr("failureStage_" + $0) + "\n" } ?? "") + technical
        refreshCriticalDetails()
    }
    private func fitCriticalContent() {
        guard let panel = criticalPanel, let title = criticalTitle, let body = criticalBody,
              let technical = criticalTechnical, let risk = criticalRisk else { return }
        var heights: [CGFloat] = []
        for (field, width) in [(title, CGFloat(270)), (body, 320), (technical, 306), (risk, 320)] {
            let rect = (field.stringValue as NSString).boundingRect(with: NSSize(width: width, height: 10000),
                options: [.usesLineFragmentOrigin, .usesFontLeading], attributes: [.font: field.font ?? NSFont.systemFont(ofSize: 14)])
            let height = max(18, ceil(rect.height) + 2)
            if field === technical {
                technical.frame = NSRect(x: 0, y: 0, width: width, height: height)
                criticalTechnicalHeight?.constant = min(96, height)
                if !field.isHidden { heights.append(min(96, height)) }
            } else { criticalHeights[ObjectIdentifier(field)]?.constant = height }
            if field === title { heights.append(max(21, height)) }
            else if field === technical { continue }
            else if !field.isHidden { heights.append(height) }
        }
        if criticalButtons?.isHidden == false { heights.append(24) }
        let height = heights.reduce(0, +) + CGFloat(max(0, heights.count - 1)) * 6 + 20
        panel.setContentSize(NSSize(width: 340, height: height))
        panel.contentView?.layoutSubtreeIfNeeded()
        if let scroll = criticalTechnicalScroll {
            scroll.contentView.scroll(to: NSPoint(x: 0, y: max(0, technical.frame.height - scroll.contentSize.height)))
            scroll.reflectScrolledClipView(scroll.contentView)
        }
        positionCriticalAlert()
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
        criticalTechnical?.stringValue = ""
        criticalIcon?.image = NSImage(systemSymbolName: "checkmark.shield.fill", accessibilityDescription: nil)
        criticalIcon?.contentTintColor = .systemGreen
        refreshCriticalDetails()
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
        let value = (currentState()["state"] as? [String:Any]) ?? [:]
        onAction?(["action": value["approvalRequired"] as? Bool == true ? "riskDetails" : (criticalTechnical?.stringValue.isEmpty == false ? "logs" : "settings")])
    }
    @objc private func approveCriticalExit() { onAction?(["action":"approveIP"]) }
    func refreshCriticalDetails() {
        guard criticalPanel != nil else { return }
        let state = (currentState()["state"] as? [String:Any]) ?? [:]
        let pending = state["approvalRequired"] as? Bool == true && !notice.recovered
        criticalButtons?.isHidden = notice.recovered
        criticalTechnical?.isHidden = notice.recovered || criticalTechnical?.stringValue.isEmpty != false
        criticalTechnicalScroll?.isHidden = criticalTechnical?.isHidden != false
        criticalBody?.isHidden = criticalBody?.stringValue.isEmpty == true
        criticalRisk?.isHidden = !pending
        criticalApprove?.isHidden = !pending
        criticalApprove?.isEnabled = state["canApproveExit"] as? Bool == true
        criticalApprove?.title = tr(state["approvalSending"] as? Bool == true ? "confirmingExit" : "approveExitAction")
        criticalReview?.title = tr(pending ? "riskSources" : (criticalTechnical?.stringValue.isEmpty == false ? "viewErrorLog" : "reviewConnection"))
        if pending {
            let report = state["reputation"] as? [String:Any]
            let fresh = !GuardReportFreshness.stale(time: report?["checked_at"] as? String ?? "", invalidatedAt: "", maxAge: 3600)
            if fresh, let score = report?["score"] as? NSNumber, (1...100).contains(score.doubleValue) {
                let coverage = (report?["scored_sources"] as? NSNumber)?.intValue ?? 0
                let detail = coverage < 2 ? "riskLimited" : (report?["complete"] as? Bool == true ? "riskReference" : "riskProvisional")
                criticalRisk?.stringValue = tr("ipRisk") + ": " + score.stringValue + "% · " + tr(detail)
                criticalRisk?.textColor = NSColor(calibratedHue: CGFloat(100-score.doubleValue)/99/3, saturation: 0.65, brightness: 0.65, alpha: 1)
            } else {
                criticalRisk?.stringValue = tr("ipRisk") + ": " + tr("riskUnknown")
                criticalRisk?.textColor = .secondaryLabelColor
            }
        }
        fitCriticalContent()
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
        let available = noticeAnchor?.window?.screen?.visibleFrame.height ?? NSScreen.main?.visibleFrame.height ?? 800
        popover.contentSize = NSSize(width: 360, height: min(600, available - 70))
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
