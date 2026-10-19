//
//  Utils.swift
//  micromanage-extra
//
//  Created by Liem Eldert on 2026/10/05.
//

import AppKit
import Darwin
import Foundation
import SwiftUI
import UserNotifications
import os

let logger = Logger(subsystem: MicromanageIdentity.appIdentifier, category: "app")

enum WindowID {
    static let daemonOnboard = "onboardDaemon"
    static let firstLaunch = "onboardFirstLaunch"
}

// One place for modal messages, so an error during startup and one during a request look the same.
final class AlertController {
    var suppressErrors = false

    func show(_ text: String, error: Bool = true) {
        logger.log("alert (error=\(error)): \(text, privacy: .public)")
        if error && suppressErrors {
            return
        }
        let alert = NSAlert()
        alert.messageText = text
        alert.alertStyle = error ? .warning : .informational
        alert.runModal()
    }
}

// True under a debugger, which is what tells a run from the IDE apart from an installed copy.
func isDebuggerAttached() -> Bool {
    var info = kinfo_proc()
    var size = MemoryLayout<kinfo_proc>.stride
    var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
    guard sysctl(&mib, UInt32(mib.count), &info, &size, nil, 0) == 0 else {
        return false
    }
    return (info.kp_proc.p_flag & P_TRACED) != 0
}

func exitApplication() {
    if isDebuggerAttached() {
        logger.info("running under a debugger, not exiting")
        return
    }
    NSApp.terminate(nil)
}

func restartApplication() {
    let task = Process()
    task.executableURL = URL(fileURLWithPath: "/bin/sh")
    task.arguments = ["-c", "sleep 1; /usr/bin/open \"\(Bundle.main.bundlePath)\""]
    try? task.run()
    exitApplication()
}

func requestNotificationAuthorization() {
    UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { granted, error in
        if let error {
            logger.error("notification authorization failed: \(error.localizedDescription, privacy: .public)")
        } else if !granted {
            logger.info("notifications are not allowed")
        }
    }
}

func postNotification(title: String, body: String) {
    let content = UNMutableNotificationContent()
    content.title = title
    content.body = body
    content.sound = .default
    let request = UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil)
    UNUserNotificationCenter.current().add(request) { error in
        if let error {
            logger.error("notification failed: \(error.localizedDescription, privacy: .public)")
        }
    }
}

// Keeps a window above the others, for the onboarding windows a user has to act on.
struct AlwaysOnTopModifier: ViewModifier {
    func body(content: Content) -> some View {
        content.background(WindowLevelAdjuster())
    }

    private struct WindowLevelAdjuster: NSViewRepresentable {
        func makeNSView(context: Context) -> NSView {
            NSView()
        }

        func updateNSView(_ nsView: NSView, context: Context) {
            nsView.window?.level = .floating
        }
    }
}

extension View {
    func alwaysOnTop() -> some View {
        modifier(AlwaysOnTopModifier())
    }
}

extension Bundle {
    var appVersion: String { info("CFBundleShortVersionString") }
    var appBuild: String { info("CFBundleVersion") }
    var installedInApplications: Bool { bundleURL.path.hasPrefix("/Applications/") }

    private func info(_ key: String) -> String {
        object(forInfoDictionaryKey: key) as? String ?? "?"
    }
}

func relativeTime(_ date: Date?) -> String {
    guard let date else {
        return "never"
    }
    let formatter = RelativeDateTimeFormatter()
    formatter.unitsStyle = .short
    return formatter.localizedString(for: date, relativeTo: Date())
}

func minutesText(_ seconds: Int) -> String {
    if seconds >= 60 {
        return "\(seconds / 60) min"
    }
    return "\(seconds) s"
}
