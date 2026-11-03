import Foundation
import CoreGraphics

// Presentation only: never changes proxy policy or approves a new exit.
struct GuardConnectionPresentation {
    var statusKey = "idle"
    var reason = ""
    var approvalRequired = false
    var observedIP = ""
    var observedCountry = ""
    var observedAt = ""
    var invalidatedAt = ""
    var hasFailure: Bool { ["approvalRequired", "connectionFailed", "paused"].contains(statusKey) }
    var titleKey: String { hasFailure ? statusKey : "" }

    mutating func beginCheck() { if !approvalRequired { statusKey = "checkBusy" } }

    mutating func receive(_ row: [String: Any]) {
        let kind = row["kind"] as? String ?? ""
        let time = row["time"] as? String ?? ISO8601DateFormatter().string(from: Date())
        switch kind {
        case "EGRESS_OK", "IP_CHANGED":
            observedIP = row["ip"] as? String ?? ""
            observedCountry = row["country"] as? String ?? ""
            observedAt = time
            if kind == "IP_CHANGED" {
                approvalRequired = true; statusKey = "approvalRequired"
                reason = row["message"] as? String ?? "出口发生变化，请重新核验并批准。"
                invalidatedAt = time
            }
        case "CHECK_FAILED", "BLOCKED", "RESUME_FAILED":
            invalidatedAt = time
            if approvalRequired { statusKey = "approvalRequired" }
            else {
                statusKey = kind == "CHECK_FAILED" ? "connectionFailed" : "paused"
                reason = row["message"] as? String ?? "连接检查未通过，请查看日志。"
            }
        case "RESUMING": if !approvalRequired { statusKey = "checkBusy" }
        case "IP_APPROVED":
            approvalRequired = false; reason = ""; statusKey = "checkBusy"
        case "CHECK_COMPLETE", "RUNNING", "RESUMED":
            approvalRequired = false; reason = ""
            statusKey = kind == "CHECK_COMPLETE" ? "idle" : "running"
        case "IDLE":
            if !approvalRequired { statusKey = "idle"; reason = "" }
        default: break
        }
    }

    mutating func backendEnded() {
        if statusKey == "checkBusy" {
            statusKey = "connectionFailed"
            reason = "连接检查未完成，请查看日志后重试。"
        } else if statusKey == "running" {
            statusKey = "paused"
            reason = "连接保护后台已结束，请退出 Claude 后重新启动。"
        }
    }

    mutating func restoreHistory() {
        // Past success never proves a connection is currently protected.
        if ["running", "checkBusy"].contains(statusKey) { statusKey = "idle" }
    }
}

enum GuardReportFreshness {
    static func date(_ value: String) -> Date? {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter.date(from: value) ?? ISO8601DateFormatter().date(from: value)
    }
    static func stale(time: String, invalidatedAt: String, maxAge: TimeInterval, now: Date = Date()) -> Bool {
        guard let observed = date(time) else { return true }
        if observed > now || now.timeIntervalSince(observed) > maxAge { return true }
        if let invalidated = date(invalidatedAt), observed <= invalidated { return true }
        return false
    }
}

enum GuardNoticeDelivery {
    // A critical in-app window is independent of notification authorization,
    // delivery failures, disabled banners, and Focus settings.
    static func send(alarm: Bool, deliverSystem: Bool = true, showInApp: () -> Void,
                     authorize: (@escaping (Bool, Error?) -> Void) -> Void,
                     post: @escaping (@escaping (Error?) -> Void) -> Void,
                     record: @escaping ([String: Any]) -> Void) {
        if alarm { showInApp() }
        if !deliverSystem { return }
        authorize { granted, error in
            guard granted else {
                record(failure("NOTIFICATION_AUTH_FAILED", error))
                return
            }
            post { error in
                if let error = error { record(failure("NOTIFICATION_SEND_FAILED", error)) }
            }
        }
    }
    private static func failure(_ kind: String, _ error: Error?) -> [String: Any] {
        var row: [String: Any] = ["kind": kind]
        if let error = error as NSError? {
            row["domain"] = error.domain; row["code"] = error.code
            row["message"] = error.localizedDescription
        }
        return row
    }
}

struct GuardNoticePresentation {
    private(set) var visible = false
    private(set) var recovered = false
    private var revision = 0
    mutating func show() { revision += 1; visible = true; recovered = false }
    mutating func dismiss() { revision += 1; visible = false; recovered = false }
    mutating func recover() -> Int? {
        guard visible else { return nil }
        revision += 1; recovered = true
        return revision
    }
    mutating func expire(_ token: Int) -> Bool {
        guard visible && recovered && revision == token else { return false }
        visible = false
        return true
    }
}

enum GuardNoticePlacement {
    static func origin(anchor: CGRect?, visibleFrame: CGRect, size: CGSize) -> CGPoint {
        let margin: CGFloat = 8
        let right = anchor?.maxX ?? visibleFrame.maxX
        let top = anchor?.minY ?? visibleFrame.maxY
        return CGPoint(x: max(visibleFrame.minX + margin, min(right - size.width, visibleFrame.maxX - size.width - margin)),
                       y: max(visibleFrame.minY + margin, min(top - size.height - margin, visibleFrame.maxY - size.height - margin)))
    }
}
