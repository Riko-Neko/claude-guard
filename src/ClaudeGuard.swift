import AppKit
import UserNotifications
import SystemConfiguration
import Darwin

final class AppDelegate: NSObject, NSApplicationDelegate, UNUserNotificationCenterDelegate, NSMenuDelegate {
    var item: NSStatusItem!
    var brandImage: NSImage?
    var launchItem: NSMenuItem!
    var checkItem: NSMenuItem!
    var statusItem: NSMenuItem!
    var backend: Process?
    var setupProcess: Process?
    var setupItem: NSMenuItem!
    var leakProcess: Process?
    var leakPending = Data()
    var pipe: Pipe?
    var pending = Data()
    var approvedPID: Int32?
    var blocked = false
    var resuming = false
    var connection = GuardConnectionPresentation()
    var store: SCDynamicStore?
    var source: CFRunLoopSource?
    var externalWarnings = Set<pid_t>()
    var latestIP = "未记录"
    var latestCountry = "未记录"
    var latestCheckTime = ""
    var selectedProtection = "proxy"
    var exitAllowed = false
    var lastCheckText = "尚未检查连接"
    let interface = GuardInterface()
    var setupInput: Pipe?
    var setupPending = Data()
    var uninstallTimer: Timer?
    var pendingLifecycleAction: String?
    var lifecycleBusy = false
    var setupActive = false
    var restartSetup = false
    var environmentInterval = 3600
    let root = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent("Library/Application Support/Claude Guard/Runtime")
    var pythonExecutable: URL {
        let candidates = ["/opt/homebrew/bin/python3", "/usr/local/bin/python3", "/usr/bin/python3"]
        return URL(fileURLWithPath: candidates.first(where: { FileManager.default.isExecutableFile(atPath: $0) }) ?? candidates[0])
    }

    func prepareRuntime() throws {
        let files = FileManager.default
        guard let payload = Bundle.main.resourceURL?.appendingPathComponent("Runtime") else {
            throw NSError(domain: "ClaudeGuard", code: 1)
        }
        let generationURL = URL(fileURLWithPath: "/Library/Application Support/Claude Guard/package-installation-id")
        let generation = (try? String(contentsOf: generationURL, encoding: .utf8)) ?? "manual-install"
        let marker = root.appendingPathComponent("installation-id")
        let previous = try? String(contentsOf: marker, encoding: .utf8)
        if previous != generation && files.fileExists(atPath: root.path) {
            let archive = root.deletingLastPathComponent().appendingPathComponent("Previous Installs")
            try files.createDirectory(at: archive, withIntermediateDirectories: true)
            try files.moveItem(at: root, to: archive.appendingPathComponent(UUID().uuidString))
        }
        try files.createDirectory(at: root, withIntermediateDirectories: true,
                                  attributes: [.posixPermissions: 0o700])
        // Refresh only shipped code. Personal settings and logs never enter the app bundle.
        for name in ["src", "tools", "tests", "README.md", "README.zh-CN.md", "LICENSE", "THIRD_PARTY_NOTICES.md", "assets", "settings.example.json"] {
            let destination = root.appendingPathComponent(name)
            if files.fileExists(atPath: destination.path) { try files.removeItem(at: destination) }
            try files.copyItem(at: payload.appendingPathComponent(name), to: destination)
        }
        try files.createDirectory(at: root.appendingPathComponent("runtime"), withIntermediateDirectories: true,
                                  attributes: [.posixPermissions: 0o700])
        let settings = root.appendingPathComponent("settings.json")
        if !files.fileExists(atPath: settings.path) {
            try files.copyItem(at: root.appendingPathComponent("settings.example.json"), to: settings)
            try files.setAttributes([.posixPermissions: 0o600], ofItemAtPath: settings.path)
        }
        try generation.write(to: marker, atomically: true, encoding: .utf8)
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        if ProcessInfo.processInfo.arguments.contains("--preview-ui") {
            exitAllowed = true
            item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
            item.button?.image = NSImage(systemSymbolName:"shield",accessibilityDescription:"Guard Preview")
            item.button?.target = self; item.button?.action = #selector(togglePanel)
            interface.noticeAnchor = item.button
            interface.state = { [weak self] in ["mode":"proxy", "interval":3600,"ip":"—", "allowed":true,"statusText":self?.interface.tr("idle") ?? "Idle"] }
            interface.onAction = { [weak self] body in
                guard let self = self, let action = body["action"] as? String else { return }
                if action == "quit" { NSApp.terminate(nil) }
                if action == "settings" { self.interface.showSettings() }
                if action == "startSetup" {
                    self.interface.emit(["kind":"request", "id":1,"title":"确认 Claude 使用的 VPN", "buttons":["取消","保存并继续"],"details":["proxy_group":"AI","expected_node":"Preview node","expected_ip":"203.0.113.8","expected_country":"TW"]])
                }
                if action == "reply" { self.interface.emit(["kind":"finished","success":true]) }
            }
            interface.showSettings()
            return
        }
        do { try prepareRuntime() }
        catch {
            let alert = NSAlert()
            alert.messageText = interface.tr("无法准备 Claude Guard")
            alert.informativeText = interface.tr("运行文件未能完整准备，请重新安装。\n\(error.localizedDescription)")
            alert.runModal()
            exitAllowed = true
            NSApp.terminate(nil)
            return
        }
        item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        if let url = Bundle.main.url(forResource: "GuardMenu", withExtension: "png"), let image = NSImage(contentsOf: url) {
            image.size = NSSize(width: 20, height: 20)
            image.isTemplate = false
            brandImage = image
        }
        item.button?.image = brandImage ?? NSImage(systemSymbolName: "shield", accessibilityDescription: "Claude Guard")
        item.button?.toolTip = "Claude Guard · 待机"
        let menu = NSMenu()
        menu.autoenablesItems = false
        menu.delegate = self
        statusItem = NSMenuItem(title: "待机 · Claude 未连接", action: nil, keyEquivalent: "")
        statusItem.isEnabled = false
        menu.addItem(statusItem)
        menu.addItem(.separator())
        launchItem = NSMenuItem(title: "检查并启动 Claude", action: #selector(launchClaude), keyEquivalent: "")
        checkItem = NSMenuItem(title: "检查 VPN 连接", action: #selector(checkOnly), keyEquivalent: "")
        for entry in [launchItem!, checkItem!] { entry.target = self; menu.addItem(entry) }
        let result = NSMenuItem(title: "查看连接检查结果", action: #selector(showResult), keyEquivalent: "")
        result.target = self; menu.addItem(result)
        let setup = NSMenuItem(title: "设置 VPN／重新核验并批准出口…", action: #selector(openInstaller), keyEquivalent: "")
        setup.target = self; menu.addItem(setup); setupItem = setup
        let stop = NSMenuItem(title: "断开 Claude 连接", action: #selector(stopSession), keyEquivalent: "")
        stop.target = self; menu.addItem(stop)
        menu.addItem(.separator())
        for (title, action) in [("查看使用说明", #selector(showHelp)), ("查看日志", #selector(showLogs)),
                                ("查看环境检查结果", #selector(showEnvironment)),
                                ("WebRTC 本地检查…", #selector(openLeakWizard)),
                                ("卸载 Claude Guard 与网络保护…", #selector(uninstall)),
                                ("退出 Claude Guard 与网络保护", #selector(quit))] {
            let entry = NSMenuItem(title: title, action: action, keyEquivalent: "")
            entry.target = self; menu.addItem(entry)
        }
        // A compact, consistently styled popover replaces the system text menu.
        interface.state = { [weak self] in self?.interfaceState() ?? [:] }
        interface.onAction = { [weak self] body in self?.interfaceAction(body) }
        item.button?.target = self
        item.button?.action = #selector(togglePanel)
        interface.noticeAnchor = item.button
        loadLastCheck()
        refreshAvailability()
        UNUserNotificationCenter.current().delegate = self
        // No network work and no Claude launch on app startup.
        installNetworkWatcher()
        installPowerWatcher()
        NSWorkspace.shared.notificationCenter.addObserver(self, selector: #selector(appLaunched(_:)),
            name: NSWorkspace.didLaunchApplicationNotification, object: nil)
        for app in NSWorkspace.shared.runningApplications { inspectExternal(app) }
        if ProcessInfo.processInfo.arguments.contains("--setup") || !protectedLaunchAllowed() {
            DispatchQueue.main.async { self.openInstaller() }
        }
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        openInstaller()
        return false
    }

    func notify(_ title: String, _ body: String, alarm: Bool = false) {
        let center = UNUserNotificationCenter.current()
        let heading = interface.tr(title), detail = interface.tr(body)
        GuardNoticeDelivery.send(alarm: alarm, deliverSystem: !alarm, showInApp: { [weak self] in
            DispatchQueue.main.async { self?.interface.showCriticalAlert(title: heading, body: detail) }
        }, authorize: { reply in
            center.requestAuthorization(options: [.alert, .sound], completionHandler: reply)
        }, post: { reply in
            let content = UNMutableNotificationContent()
            content.title = heading; content.body = detail
            if alarm { content.sound = .default }
            center.add(UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil),
                       withCompletionHandler: reply)
        }, record: { [weak self] row in self?.recordPresentationEvent(row) })
    }

    func recordPresentationEvent(_ fields: [String: Any]) {
        var row = fields
        row["time"] = ISO8601DateFormatter().string(from: Date())
        guard var data = try? JSONSerialization.data(withJSONObject: row) else { return }
        data.append(10)
        let path = root.appendingPathComponent("runtime/ui-events.jsonl").path
        let descriptor = open(path, O_WRONLY | O_CREAT | O_APPEND, mode_t(0o600))
        guard descriptor >= 0 else { return }
        fchmod(descriptor, mode_t(0o600))
        let file = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        try? file.write(contentsOf: data)
        try? file.close()
    }

    func userNotificationCenter(_ center: UNUserNotificationCenter,
        willPresent notification: UNNotification,
        withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) {
        completionHandler([.banner, .sound])
    }

    func display(_ text: String, symbol: String) {
        statusItem.title = interface.tr(text)
        item.button?.image = brandImage ?? NSImage(systemSymbolName: symbol, accessibilityDescription: text)
        item.button?.toolTip = interface.tr(text)
        interface.refreshMenu()
    }

    @objc func togglePanel() {
        guard let button = item.button else { return }
        interface.toggleMenu(relativeTo: button)
    }

    func interfaceState() -> [String: Any] {
        let status = resuming ? "checkBusy" : (setupProcess != nil ? "busy" : connection.statusKey)
        let settings = ((try? Data(contentsOf: root.appendingPathComponent("settings.json")))
            .flatMap { try? JSONSerialization.jsonObject(with: $0) }) as? [String: Any] ?? [:]
        return ["mode": configuredProtection(), "interval": environmentInterval, "configured": protectedLaunchAllowed(),
                "ip": latestIP == "未记录" ? "—" : latestIP, "region": latestCountry, "allowed": protectedLaunchAllowed(),
                "approvedIP": settings["configured"] as? Bool == true ? (settings["expected_ip"] as? String ?? "—") : "—",
                "observedAt": connection.observedAt,
                "invalidatedAt": connection.invalidatedAt,
                "group": settings["proxy_group"] as? String ?? "—", "node": settings["expected_node"] as? String ?? "—",
                "approvalRequired": connection.approvalRequired,
                "connectionTitle": interface.tr(connection.titleKey), "connectionReason": connection.hasFailure ? interface.tr(connection.reason) : "",
                "active": backend != nil, "paused": backend != nil && blocked,
                "busy": setupProcess != nil || resuming,
                "statusText": interface.tr(status)]
    }

    func interfaceAction(_ body: [String: Any]) {
        guard let action = body["action"] as? String else { return }
        switch action {
        case "startSetup":
            guard let mode = body["mode"] as? String, ["proxy", "enhanced"].contains(mode),
                  let interval = body["interval"] as? Int, [900,3600,10800].contains(interval) else { return }
            environmentInterval = interval
            restartSetup = body["restart"] as? Bool == true
            beginSetup(mode)
        case "reply":
            guard let input = setupInput, let id = body["id"] as? Int else { return }
            var answer: [String: Any] = ["id": id]
            if let index = body["index"] as? Int { answer["index"] = index }
            if let value = body["value"] as? String { answer["value"] = value }
            if var data = try? JSONSerialization.data(withJSONObject: answer) {
                data.append(10)
                try? input.fileHandleForWriting.write(contentsOf: data)
            }
        case "closeClaude":
            let alert = NSAlert()
            alert.messageText = interface.tr("closeClaude")
            alert.addButton(withTitle: interface.tr("continue"))
            alert.runModal()
        case "settings": openInstaller()
        case "launch": interface.closeMenu(); launchClaude()
        case "check": checkOnly()
        case "pause": stopSession()
        case "results": showEnvironment()
        case "localChecks": openLeakWizard()
        case "help": showHelp()
        case "logs": showLogs()
        case "closeSettings":
            if setupProcess == nil && protectedLaunchAllowed() {
                interface.closeSettings()
                notify("done", "doneBody")
            }
        case "quit":
            interface.closeMenu()
            DispatchQueue.main.async { self.quit() }
        case "uninstall":
            interface.closeMenu()
            // Leave the WebKit message callback/popover transition before modal UI.
            DispatchQueue.main.async { self.uninstall() }
        default: break
        }
    }

    func configuredProtection() -> String {
        guard let data = try? Data(contentsOf: root.appendingPathComponent("settings.json")),
              let settings = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else { return "proxy" }
        return settings["protection_mode"] as? String ?? (settings["configured"] as? Bool == true ? "enhanced" : "proxy")
    }

    func hasConfiguredProfile() -> Bool {
        guard let data = try? Data(contentsOf: root.appendingPathComponent("settings.json")),
              let settings = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else { return false }
        return settings["configured"] as? Bool == true
    }

    @objc func launchClaude() {
        guard setupProcess == nil && !resuming else { return }
        if connection.approvalRequired { openInstaller(); return }
        if let process = backend {
            guard blocked && process.isRunning else { return }
            resuming = true
            refreshAvailability()
            display("正在重新检查连接…", symbol: "shield.lefthalf.filled")
            kill(process.processIdentifier, SIGHUP)
            return
        }
        selectedProtection = configuredProtection()
        if !protectedLaunchAllowed() { openInstaller(); return }
        start("launch")
    }
    @objc func checkOnly() { start("check") }

    func protectedLaunchAllowed() -> Bool {
        guard let data = try? Data(contentsOf: root.appendingPathComponent("settings.json")),
              let settings = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else { return false }
        return settings["protected_launch_enabled"] as? Bool == true
    }

    func refreshAvailability() {
        let allowed = protectedLaunchAllowed()
        launchItem.title = connection.approvalRequired ? interface.tr("reviewExitAction") : (allowed ? (backend != nil && blocked ? "重新检查并恢复连接" : "检查并启动 Claude") : "完成设置后可启动 Claude")
        launchItem.isEnabled = allowed && (backend == nil || blocked) && setupProcess == nil && !resuming
        checkItem.isEnabled = backend == nil && setupProcess == nil
        setupItem?.isEnabled = backend == nil && setupProcess == nil
    }

    func menuNeedsUpdate(_ menu: NSMenu) { refreshAvailability() }

    func saveCheckSummary(_ row: [String: Any]) {
        latestCheckTime = row["time"] as? String ?? "时间未记录"
        let short = latestCheckTime.count >= 19 ? String(latestCheckTime.dropFirst(11).prefix(8)) : latestCheckTime
        lastCheckText = "上次检查通过 \(short) · \(latestIP) (\(latestCountry))"
    }

    func loadLastCheck() {
        connection = GuardConnectionPresentation()
        let files = (try? FileManager.default.contentsOfDirectory(at: root.appendingPathComponent("runtime"),
            includingPropertiesForKeys: nil)) ?? []
        for url in files.filter({ $0.pathExtension == "jsonl" }).sorted(by: { $0.lastPathComponent < $1.lastPathComponent }) {
            guard let text = try? String(contentsOf: url, encoding: .utf8) else { continue }
            for line in text.split(separator: "\n") {
                guard let data = String(line).data(using: .utf8),
                      let row = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else { continue }
                if row["kind"] as? String == "EGRESS_OK" {
                    latestIP = row["ip"] as? String ?? "未记录"
                    latestCountry = row["country"] as? String ?? "未记录"
                }
                if row["kind"] as? String == "IP_CHANGED" {
                    latestIP = row["ip"] as? String ?? "未记录"
                    latestCountry = row["country"] as? String ?? "未记录"
                }
                connection.receive(row)
                if row["kind"] as? String == "CHECK_COMPLETE" { saveCheckSummary(row) }
            }
        }
        connection.restoreHistory()
        blocked = connection.hasFailure
        display(connection.hasFailure ? interface.tr(connection.titleKey) : lastCheckText, symbol: connection.hasFailure ? "exclamationmark.shield.fill" : "shield")
    }

    @objc func showResult() { showEnvironment() }

    func start(_ action: String) {
        guard backend == nil && setupProcess == nil else { return }
        if action == "launch" && !protectedLaunchAllowed() { return }
        let process = Process()
        process.executableURL = pythonExecutable
        process.arguments = [root.appendingPathComponent("src/guard.py").path, action,
                             "--protection", action == "launch" ? selectedProtection : configuredProtection()]
        var env = GuardChildEnvironment.make(ProcessInfo.processInfo.environment, language: interface.language)
        env["CLAUDE_GUARD_UI_PID"] = String(getpid())
        env["PYTHONUNBUFFERED"] = "1"
        env["CLAUDE_GUARD_LANGUAGE"] = interface.language
        process.environment = env
        let output = Pipe()
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        pipe = output; backend = process; approvedPID = nil; blocked = false; resuming = false; pending = Data()
        connection.beginCheck()
        launchItem.isEnabled = false; checkItem.isEnabled = false
        display("正在检查连接…", symbol: "shield.lefthalf.filled")
        output.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            if data.isEmpty { return }
            DispatchQueue.main.async {
                guard self?.backend === process else { return }
                self?.consume(data)
            }
        }
        process.terminationHandler = { [weak self] process in
            DispatchQueue.main.async {
                guard let self = self else { return }
                guard self.backend === process else { return }
                self.pipe?.fileHandleForReading.readabilityHandler = nil
                self.backend = nil; self.pipe = nil; self.approvedPID = nil; self.resuming = false
                let hadFailure = self.connection.hasFailure
                self.connection.backendEnded()
                self.blocked = self.connection.hasFailure
                self.refreshAvailability()
                if self.continuePendingLifecycle() { return }
                if self.connection.hasFailure {
                    self.display(self.interface.tr(self.connection.titleKey), symbol: "exclamationmark.shield.fill")
                    if !hadFailure {
                        self.notify(self.connection.titleKey, self.connection.reason, alarm: true)
                    }
                } else if !self.blocked {
                    if process.terminationStatus != 0 {
                        self.display("连接检查未完成", symbol: "shield.slash.fill")
                        self.notify("连接检查未完成", "请检查 Clash 的运行状态和所选节点，然后重新检查连接。", alarm: true)
                    } else {
                        self.display(self.lastCheckText, symbol: "shield")
                    }
                }
            }
        }
        do { try process.run() }
        catch {
            backend = nil; pipe = nil
            connection.backendEnded(); blocked = true
            refreshAvailability()
            display("连接保护无法启动", symbol: "shield.slash.fill")
            notify("Claude Guard 无法运行", "请重新打开 Guard，或重新安装。", alarm: true)
        }
    }

    func consume(_ data: Data) {
        pending.append(data)
        while let newline = pending.firstIndex(of: 10) {
            let line = pending.subdata(in: pending.startIndex..<newline)
            pending.removeSubrange(pending.startIndex...newline)
            guard let row = (try? JSONSerialization.jsonObject(with: line)) as? [String: Any],
                  let kind = row["kind"] as? String else { continue }
            connection.receive(row)
            switch kind {
            case "EGRESS_OK":
                latestIP = row["ip"] as? String ?? "未记录"
                latestCountry = row["country"] as? String ?? "未记录"
                saveCheckSummary(row)
            case "RUNNING":
                approvedPID = (row["pid"] as? NSNumber)?.int32Value
                let recovered = interface.showRecoveredNotice(title: interface.tr("connectionRecovered"), body: interface.tr("connectionRecoveryBody"))
                display("Claude 连接保护已开启", symbol: "checkmark.shield.fill")
                if !recovered { notify("连接保护已开启", "连接检查已通过，Claude 正在使用已设置的 VPN。") }
            case "RESUMING":
                resuming = true
                display("正在重新检查连接…", symbol: "shield.lefthalf.filled")
            case "RESUMED":
                blocked = false; resuming = false
                interface.showRecoveredNotice(title: interface.tr("connectionRecovered"), body: interface.tr("connectionRecoveryBody"))
                display("Claude 连接保护已开启", symbol: "checkmark.shield.fill")
            case "RESUME_FAILED":
                blocked = true; resuming = false
                if connection.approvalRequired {
                    display(interface.tr("approvalRequired"), symbol: "exclamationmark.shield.fill")
                    break
                }
                let retrying = row["retrying"] as? Bool == true
                display(retrying ? "等待网络恢复…" : "Claude 连接已暂停", symbol: "exclamationmark.shield.fill")
                // Automatic transient retries do not repeat the same alarm.
                if row["automatic"] as? Bool != true || !retrying {
                    notify("连接尚未恢复", row["message"] as? String ?? "请确认 VPN 连接后重试。", alarm: true)
                }
            case "BLOCKED":
                let alreadyBlocked = blocked
                blocked = true
                if connection.approvalRequired { break }
                display("Claude 连接已暂停", symbol: "exclamationmark.shield.fill")
                if !alreadyBlocked { notify("Claude 连接已暂停", row["message"] as? String ?? "VPN 状态发生变化，Claude 的受保护连接已断开。请退出 Claude、检查 VPN，再从 Guard 菜单重新启动。", alarm: true) }
            case "IP_CHANGED":
                blocked = true
                latestIP = row["ip"] as? String ?? "未记录"
                latestCountry = row["country"] as? String ?? "未记录"
                display("出口变化 · 等待人为批准", symbol: "exclamationmark.shield.fill")
                let settings = interfaceState()
                let body = interface.tr("approvedIP") + ": " + (settings["approvedIP"] as? String ?? "—") + "\n" +
                    interface.tr("observedIP") + ": " + latestIP + " (" + latestCountry + ")\n\n" + interface.tr("exitApprovalBody")
                notify("出口 IP 发生变化", body, alarm: true)
            case "ENVIRONMENT_WARNING", "LEAK_WARNING":
                if !blocked { display("环境检查需要复查 · 连接未暂停", symbol: "exclamationmark.shield") }
                notify("网络环境检查提醒", row["message"] as? String ?? "请查看环境检查结果。", alarm: true)
            case "CHECK_FAILED":
                blocked = true
                if connection.approvalRequired {
                    display(interface.tr("approvalRequired"), symbol: "exclamationmark.shield.fill")
                    break
                }
                display("连接检查未通过", symbol: "exclamationmark.shield.fill")
                notify("连接检查未通过", row["message"] as? String ?? "本次未启动 Claude。", alarm: true)
            case "CHECK_COMPLETE":
                blocked = false
                let recovered = interface.showRecoveredNotice(title: interface.tr("checkPassedNotice"), body: interface.tr("checkPassedNoticeBody"))
                saveCheckSummary(row)
                display(lastCheckText, symbol: "checkmark.shield")
                if !recovered { notify("网络检查通过", "当前 VPN 与已保存的设置一致。可以从菜单检查并启动 Claude。") }
            case "IDLE":
                blocked = true
                display("待机 · Claude 未连接", symbol: "shield")
            default: break
            }
            refreshAvailability()
        }
    }

    func installNetworkWatcher() {
        var context = SCDynamicStoreContext(version: 0,
            info: Unmanaged.passUnretained(self).toOpaque(), retain: nil, release: nil, copyDescription: nil)
        store = SCDynamicStoreCreate(nil, "ClaudeGuard" as CFString, { _, changedKeys, info in
            guard let info = info else { return }
            let keys = changedKeys as NSArray as? [String] ?? []
            let dnsOnly = !keys.isEmpty && keys.allSatisfy { $0.hasSuffix("/DNS") }
            let object = Unmanaged<AppDelegate>.fromOpaque(info).takeUnretainedValue()
            DispatchQueue.main.async {
                if let process = object.backend, process.isRunning {
                    kill(process.processIdentifier, dnsOnly ? SIGURG : SIGUSR1)
                }
            }
        }, &context)
        guard let store = store else { return }
        // Ignore traffic counters; only system network configuration changes.
        let keys = ["State:/Network/Global/IPv4", "State:/Network/Global/IPv6", "State:/Network/Global/DNS"]
        SCDynamicStoreSetNotificationKeys(store, keys as CFArray, nil)
        source = SCDynamicStoreCreateRunLoopSource(nil, store, 0)
        if let source = source { CFRunLoopAddSource(CFRunLoopGetMain(), source, .defaultMode) }
    }

    func installPowerWatcher() {
        let center = NSWorkspace.shared.notificationCenter
        for name in [NSWorkspace.willSleepNotification, NSWorkspace.didWakeNotification] {
            center.addObserver(self, selector: #selector(powerChanged(_:)), name: name, object: nil)
        }
    }

    @objc func powerChanged(_ notification: Notification) {
        // Pause managed connections; recovery requires an explicit menu action.
        if let process = backend, process.isRunning {
            kill(process.processIdentifier, SIGUSR2)
        }
    }

    @objc func appLaunched(_ notification: Notification) {
        guard let app = notification.userInfo?[NSWorkspace.applicationUserInfoKey] as? NSRunningApplication else { return }
        DispatchQueue.main.asyncAfter(deadline: .now() + 1) { self.inspectExternal(app) }
    }

    func inspectExternal(_ app: NSRunningApplication) {
        guard protectedLaunchAllowed(), app.bundleURL?.lastPathComponent == "Claude.app",
              !app.isTerminated, backend == nil, !externalWarnings.contains(app.processIdentifier) else { return }
        externalWarnings.insert(app.processIdentifier)
        display("Claude 未通过 Guard 启动", symbol: "shield.slash")
        notify("请通过 Guard 启动 Claude", "请退出 Claude，再从盾牌菜单选择“检查并启动 Claude”。")
    }

    @objc func stopSession() {
        guard let process = backend else { return }
        if process.isRunning { process.terminate() }
        blocked = true
        connection.receive(["kind":"BLOCKED", "message":interface.tr("manualPauseReason")])
        display("Claude 连接已暂停", symbol: "shield.slash.fill")
    }

    @objc func openInstaller() {
        interface.showSettings()
    }

    func beginSetup(_ mode: String) {
        if backend != nil || setupProcess != nil {
            interface.emit(["kind":"finished", "success":false])
            interfaceAction(["action":"closeClaude"])
            return
        }
        if GuardSetupPolicy.requiresFilterShutdown(currentMode: configuredProtection(),
                                                    configured: hasConfiguredProfile(), targetMode: mode) {
            // Release only a previously enrolled filter before entering basic mode.
            performLifecycle("quit") { [weak self] in self?.runSetup(mode) }
        } else { runSetup(mode) }
    }

    func runSetup(_ mode: String) {
        guard backend == nil && setupProcess == nil else { return }
        let process = Process()
        process.executableURL = pythonExecutable
        process.environment = GuardChildEnvironment.make(ProcessInfo.processInfo.environment, language: interface.language)
        process.arguments = [root.appendingPathComponent("tools/gui_setup.py").path, "--protection", mode,
                             "--embedded", "--environment-interval", String(environmentInterval)]
        if restartSetup { process.arguments?.append("--restart") }
        let output = Pipe()
        let input = Pipe()
        process.standardInput = input
        setupInput = input
        setupPending = Data()
        process.standardOutput = output
        // Preserve native authorization/helper errors instead of discarding the
        // only explanation when setup cannot advance. Open with O_APPEND since
        // the Python setup process appends to this same private log.
        let errorPath = root.appendingPathComponent("runtime/gui-install.log").path
        let errorDescriptor = open(errorPath, O_WRONLY | O_CREAT | O_APPEND, mode_t(0o600))
        if errorDescriptor >= 0 {
            fchmod(errorDescriptor, mode_t(0o600))
            process.standardError = FileHandle(fileDescriptor: errorDescriptor, closeOnDealloc: true)
        } else { process.standardError = FileHandle.nullDevice }
        setupProcess = process
        setupActive = true
        refreshAvailability()
        display("正在配置 Claude Guard…", symbol: "shield.lefthalf.filled")
        output.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            guard !data.isEmpty else { return }
            DispatchQueue.main.async {
                guard let self = self else { return }
                self.setupPending.append(data)
                while let end = self.setupPending.firstIndex(of: 10) {
                    let line = self.setupPending.subdata(in: self.setupPending.startIndex..<end)
                    self.setupPending.removeSubrange(self.setupPending.startIndex...end)
                    if let row = (try? JSONSerialization.jsonObject(with: line)) as? [String: Any] { self.interface.emit(row) }
                }
            }
        }
        process.terminationHandler = { [weak self] finished in
            output.fileHandleForReading.readabilityHandler = nil
            DispatchQueue.main.async {
                self?.setupProcess = nil
                self?.setupActive = false
                self?.setupInput = nil
                if finished.terminationStatus == 0 && self?.protectedLaunchAllowed() == true {
                    self?.loadLastCheck()
                    self?.interface.showRecoveredNotice(title: self?.interface.tr("checkPassedNotice") ?? "", body: self?.interface.tr("checkPassedNoticeBody") ?? "")
                }
                self?.interface.emit(["kind":"finished", "success":finished.terminationStatus == 0])
                self?.refreshAvailability()
                if self?.continuePendingLifecycle() == true { return }
                self?.display(finished.terminationStatus == 0 ? "设置流程已结束 · 请从菜单继续" : "设置未完成", symbol: "shield")
            }
        }
        do { try process.run() }
        catch {
            setupProcess = nil; setupActive = false; refreshAvailability()
            setupInput = nil
            interface.emit(["kind":"finished", "success":false])
            notify("配置无法开始", "请重新打开 Guard，或重新安装。", alarm: true)
        }
    }

    @objc func showHelp() { NSWorkspace.shared.open(root.appendingPathComponent(interface.language == "zh-Hans" ? "README.zh-CN.md" : "README.md")) }
    @objc func showLogs() { NSWorkspace.shared.open(root.appendingPathComponent("runtime")) }
    @objc func showEnvironment() {
        var checks = [[String: Any]]()
        for name in ["environment-report.json", "leak-report.json"] {
            let url = root.appendingPathComponent("runtime/" + name)
            guard let data = try? Data(contentsOf: url),
                  let report = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
                  let rows = report["checks"] as? [[String: Any]] else { continue }
            checks.append(contentsOf: rows.map { row in
                var localized = row
                let timestamp = report["time"] as? String ?? ""
                localized["sourceTime"] = timestamp
                localized["stale"] = GuardReportFreshness.stale(time: timestamp, invalidatedAt: connection.invalidatedAt,
                                                               maxAge: TimeInterval(environmentInterval))
                if let message = row["message"] as? String { localized["message"] = interface.tr(message) }
                return localized
            })
        }
        interface.showSettings()
        interface.emit(["kind":"report", "checks":checks])
    }

    @objc func openLeakWizard() {
        guard leakProcess == nil else { notify("泄漏检查已打开", "请在浏览器中的 Claude Guard 检查页面继续。"); return }
        let process = Process()
        process.executableURL = pythonExecutable
        process.arguments = [root.appendingPathComponent("tools/leak_wizard.py").path]
        let output = Pipe();process.standardOutput = output;process.standardError = FileHandle.nullDevice
        leakProcess = process;leakPending = Data()
        output.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            DispatchQueue.main.async {
                guard let self = self else { return }
                self.leakPending.append(data)
                while let end = self.leakPending.firstIndex(of: 10) {
                    let line = self.leakPending.subdata(in: self.leakPending.startIndex..<end)
                    self.leakPending.removeSubrange(self.leakPending.startIndex...end)
                    if let row = (try? JSONSerialization.jsonObject(with: line)) as? [String: Any], row["kind"] as? String == "LEAK_WARNING" {
                        if !self.blocked { self.display("本地泄漏检查需要复查 · 连接未暂停", symbol: "exclamationmark.shield") }
                        self.notify("发现疑似网络泄漏", row["message"] as? String ?? "请查看检测页面。", alarm: true)
                    }
                }
            }
        }
        process.terminationHandler = { [weak self] finished in
            output.fileHandleForReading.readabilityHandler = nil
            DispatchQueue.main.async {
                self?.leakProcess = nil
                if finished.terminationStatus != 0 { self?.notify("泄漏检查已结束", "检查未完整执行，请完成 VPN 设置后重新打开。") }
            }
        }
        do { try process.run() }
        catch { leakProcess = nil; notify("无法打开泄漏检查", "请完成设置后重试。", alarm: true) }
    }
    func performLifecycle(_ action: String, completion: @escaping () -> Void) {
        if setupProcess != nil || backend != nil {
            let alert = NSAlert()
            alert.messageText = interface.tr("请先结束当前会话")
            alert.informativeText = interface.tr("operationBusy")
            alert.runModal()
            return
        }
        let process = Process()
        process.executableURL = pythonExecutable
        process.arguments = [root.appendingPathComponent("tools/lifecycle.py").path, action]
        process.environment = GuardChildEnvironment.make(ProcessInfo.processInfo.environment, language: interface.language)
        let output = Pipe()
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        setupProcess = process
        lifecycleBusy = true
        refreshAvailability()
        display(action == "uninstall" ? "正在卸载网络保护…" : "正在关闭网络保护…", symbol: "shield.lefthalf.filled")
        process.terminationHandler = { [weak self] finished in
            let remaining = output.fileHandleForReading.readDataToEndOfFile()
            DispatchQueue.main.async {
                let result = remaining
                guard let self = self else { return }
                self.setupProcess = nil
                self.lifecycleBusy = false
                self.refreshAvailability()
                if finished.terminationStatus == 0 { completion(); return }
                let row = try? JSONSerialization.jsonObject(with: result) as? [String: Any]
                let alert = NSAlert()
                let message = row?["message"] as? String ?? "请完成系统授权后重试。Guard 尚未退出或卸载。"
                if self.interface.visible {
                    self.interface.emit(["kind":"request", "id":-1, "title":"设置未完成", "body":message, "buttons":["知道了"]])
                } else {
                    alert.messageText = self.interface.tr("网络保护操作未完成")
                    alert.informativeText = self.interface.tr(message)
                    alert.runModal()
                }
                self.display("网络保护尚未关闭", symbol: "shield.slash")
            }
        }
        do { try process.run() }
        catch {
            setupProcess = nil
            lifecycleBusy = false
            refreshAvailability()
            notify("无法关闭网络保护", "操作未开始，Guard 尚未退出。", alarm: true)
        }
    }

    @objc func quit() {
        requestLifecycle("quit")
    }

    @discardableResult func continuePendingLifecycle() -> Bool {
        guard let action = pendingLifecycleAction else { return false }
        pendingLifecycleAction = nil
        requestLifecycle(action)
        return true
    }

    func requestLifecycle(_ action: String) {
        let claudeAlive = approvedPID.map { kill($0, 0) == 0 } ?? false
        let choice = GuardLifecyclePolicy.decision(setup: setupActive, operation: lifecycleBusy || uninstallTimer != nil,
                                                  backend: backend != nil, claude: claudeAlive)
        if choice == "operation" { return }
        if choice == "cancelSetup", let process = setupProcess {
            pendingLifecycleAction = action
            // Cooperative cancellation: never terminate a system operation halfway.
            kill(process.processIdentifier, SIGUSR1)
            try? setupInput?.fileHandleForWriting.close()
            setupInput = nil
            interface.emit(["kind":"phase", "message":"正在结束设置…"])
            display("endingSetup",symbol:"shield")
            return
        }
        if choice == "claude" { interfaceAction(["action":"closeClaude"]); return }
        if choice == "endCheck", let process = backend {
            pendingLifecycleAction = action
            process.terminate()
            display("endingCheck",symbol:"shield")
            return
        }
        if action == "uninstall" { beginUninstall(); return }
        performLifecycle("quit") { [weak self] in
            self?.leakProcess?.terminate()
            self?.exitAllowed = true
            NSApp.terminate(nil)
        }
    }

    @objc func uninstall() {
        let alert = NSAlert()
        alert.messageText = interface.tr("卸载 Claude Guard 与网络保护？")
        alert.informativeText = interface.tr("uninstallInfo")
        alert.addButton(withTitle: interface.tr("取消"))
        alert.addButton(withTitle: interface.tr("卸载"))
        guard alert.runModal() == .alertSecondButtonReturn else { return }
        requestLifecycle("uninstall")
    }

    func beginUninstall() {
        guard backend == nil && setupProcess == nil && uninstallTimer == nil else {
            let notice = NSAlert(); notice.messageText = interface.tr("请先结束当前会话")
            notice.informativeText = interface.tr("operationBusy"); notice.runModal(); return
        }
        let ready = root.appendingPathComponent("runtime/uninstall-\(UUID().uuidString).json")
        let logURL = root.appendingPathComponent("runtime/uninstall.log")
        FileManager.default.createFile(atPath: logURL.path, contents: nil, attributes: [.posixPermissions:0o600])
        let helper = Process()
        helper.executableURL = pythonExecutable
        helper.arguments = [root.appendingPathComponent("tools/lifecycle.py").path, "uninstall",
                            "--after-exit", String(ProcessInfo.processInfo.processIdentifier),
                            "--ready-file", ready.path, "--remove-guard", Bundle.main.bundleURL.path]
        helper.environment = GuardChildEnvironment.make(ProcessInfo.processInfo.environment, language: interface.language)
        do {
            let log = try FileHandle(forWritingTo: logURL)
            try log.seekToEnd()
            helper.standardOutput = log; helper.standardError = log
            try helper.run()
            let deadline = Date().addingTimeInterval(10)
            uninstallTimer = Timer.scheduledTimer(withTimeInterval:0.1, repeats:true) { [weak self] timer in
                guard let self = self else { timer.invalidate(); return }
                let row = (try? Data(contentsOf: ready)).flatMap { try? JSONSerialization.jsonObject(with:$0) as? [String:Any] }
                if row == nil && helper.isRunning && Date() < deadline { return }
                timer.invalidate(); self.uninstallTimer = nil
                try? FileManager.default.removeItem(at: ready)
                if row?["ready"] as? Bool == true {
                    self.leakProcess?.terminate()
                    self.exitAllowed = true
                    NSApp.terminate(nil)
                } else {
                    let notice = NSAlert(); notice.messageText = self.interface.tr("网络保护操作未完成")
                    notice.informativeText = self.interface.tr(row?["message"] as? String ?? "uninstallStartFailed")
                    notice.runModal()
                }
            }
        } catch {
            let notice = NSAlert(); notice.messageText = interface.tr("网络保护操作未完成")
            notice.informativeText = interface.tr("uninstallStartFailed"); notice.runModal()
        }
    }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        if exitAllowed { return .terminateNow }
        quit()
        return .terminateCancel
    }
}

let application = NSApplication.shared
let delegate = AppDelegate()
application.delegate = delegate
application.setActivationPolicy(.accessory)
application.run()
