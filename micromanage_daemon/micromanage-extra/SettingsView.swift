//
//  SettingsView.swift
//  micromanage-extra
//
//  Created by Liem Eldert on 2026/10/05.
//

import Combine
import Foundation
import ServiceManagement
import SwiftUI

// User-level preferences. They live in the app's own defaults domain, which a management profile can also set.
final class PreferencesState: ObservableObject {
    static let shared = PreferencesState()

    private let defaults = UserDefaults.standard

    @Published var defaultMinutes: Int {
        didSet { defaults.set(defaultMinutes, forKey: "DefaultMinutes") }
    }
    @Published var notificationWarnSeconds: Int {
        didSet { defaults.set(notificationWarnSeconds, forKey: "NotificationWarnSeconds") }
    }
    @Published var resetDefaultTime: Bool {
        didSet { defaults.set(resetDefaultTime, forKey: "ResetDefaultTime") }
    }
    @Published var firstLaunch: Bool {
        didSet { defaults.set(firstLaunch, forKey: "FirstLaunch") }
    }

    init() {
        defaultMinutes = max(1, defaults.object(forKey: "DefaultMinutes") as? Int ?? 15)
        notificationWarnSeconds = max(0, defaults.object(forKey: "NotificationWarnSeconds") as? Int ?? 120)
        resetDefaultTime = defaults.object(forKey: "ResetDefaultTime") as? Bool ?? false
        firstLaunch = defaults.object(forKey: "FirstLaunch") as? Bool ?? true
    }
}

struct SettingsView: View {
    @ObservedObject var daemon: DaemonClient
    @ObservedObject var preferences: PreferencesState

    private enum Tabs: Hashable {
        case general
        case advanced
        case about
    }

    var body: some View {
        TabView {
            GeneralSettingsView(daemon: daemon, preferences: preferences)
                .tabItem { Label("General", systemImage: "gear") }
                .tag(Tabs.general)
            AdvancedSettingsView(daemon: daemon)
                .tabItem { Label("Advanced", systemImage: "wrench.and.screwdriver") }
                .tag(Tabs.advanced)
            AboutView(daemon: daemon)
                .tabItem { Label("About", systemImage: "info.circle") }
                .tag(Tabs.about)
        }
        .frame(width: 420)
    }
}

struct GeneralSettingsView: View {
    @ObservedObject var daemon: DaemonClient
    @ObservedObject var preferences: PreferencesState

    private var maxMinutes: Int { daemon.policy?.maxMinutes ?? 60 }

    var body: some View {
        Form {
            Section {
                Stepper(value: $preferences.defaultMinutes, in: 1...max(1, maxMinutes)) {
                    TextField("Default time (minutes)", value: $preferences.defaultMinutes, format: .number)
                }
                Text("How long admin access lasts unless you pick another length. The policy limit is "
                     + "\(maxMinutes) minutes.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Toggle("Reset to the default time each time the menu opens", isOn: $preferences.resetDefaultTime)
            }
            Section {
                Stepper(value: $preferences.notificationWarnSeconds, in: 0...3600, step: 30) {
                    TextField("Warn before access ends (seconds)", value: $preferences.notificationWarnSeconds,
                              format: .number)
                }
                Text("A notification this many seconds before admin access is taken back. Zero turns it off.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
        .padding(.bottom, 8)
    }
}

struct AdvancedSettingsView: View {
    @ObservedObject var daemon: DaemonClient
    @State private var showFacts = false

    var body: some View {
        Form {
            Section("Background service") {
                LabeledContent("State", value: serviceStateText)
                HStack {
                    Button("Register") {
                        Task { await daemon.registerDaemon() }
                    }
                    Button("Unregister") {
                        daemon.unregisterDaemon()
                    }
                    Button("Refresh") {
                        daemon.refreshServiceStatus()
                        Task { await daemon.refreshStatus() }
                    }
                }
            }
            Section("Server") {
                LabeledContent("Configured", value: (daemon.server?.configured ?? false) ? "yes" : "no")
                LabeledContent("Enrolled", value: (daemon.server?.enrolled ?? false) ? "yes" : "no")
                LabeledContent("Last check-in", value: relativeTime(daemon.server?.lastCheckIn))
                if let error = daemon.server?.lastError, !error.isEmpty {
                    LabeledContent("Last error", value: error)
                }
                Button("Check in now") {
                    daemon.checkInNow()
                }
                .disabled(!(daemon.server?.configured ?? false))
            }
            Section("Diagnostics") {
                Button("Show what this Mac reports") {
                    showFacts = true
                    daemon.loadFacts()
                }
                Button("Quit Micromanage") {
                    exitApplication()
                }
            }
        }
        .formStyle(.grouped)
        .sheet(isPresented: $showFacts) {
            FactsSheet(daemon: daemon, isPresented: $showFacts)
        }
    }

    private var serviceStateText: String {
        switch daemon.serviceStatus {
        case .enabled:
            return "running"
        case .requiresApproval:
            return "waiting for approval in Login Items"
        case .notFound:
            return "missing"
        case .notRegistered:
            return "not registered"
        @unknown default:
            return "unknown"
        }
    }
}

struct FactsSheet: View {
    @ObservedObject var daemon: DaemonClient
    @Binding var isPresented: Bool

    var body: some View {
        VStack(alignment: .leading) {
            Text("What this Mac reports").font(.headline)
            if let facts = daemon.facts {
                ScrollView {
                    Text(facts)
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
            } else {
                ProgressView("Collecting")
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
            HStack {
                Spacer()
                Button("Close") {
                    isPresented = false
                }
                .keyboardShortcut(.cancelAction)
            }
        }
        .padding()
        .frame(width: 560, height: 480)
    }
}

struct AboutView: View {
    @ObservedObject var daemon: DaemonClient

    var body: some View {
        Form {
            LabeledContent("App", value: "\(Bundle.main.appVersion) (\(Bundle.main.appBuild))")
            LabeledContent("Background service", value: daemon.daemonVersion)
            LabeledContent("Signed in as", value: daemon.status?.username ?? NSUserName())
            if let tenant = daemon.server?.tenantID {
                LabeledContent("Managed by", value: tenant)
            }
            if let url = daemon.server?.serverURL {
                LabeledContent("Server", value: url)
            }
        }
        .formStyle(.grouped)
    }
}
