//
//  ContentView.swift
//  micromanage-extra
//
//  Created by Liem Eldert on 2026/10/05.
//

import ServiceManagement
import SwiftUI

struct ContentView: View {
    @ObservedObject var daemon: DaemonClient
    @ObservedObject var preferences: PreferencesState
    @ObservedObject var iconState: MenuBarIconState
    @State private var minutes: Int
    @State private var extraMinutes = 15
    @State private var reason = ""
    @State private var showAddTime = false

    init(daemon: DaemonClient, preferences: PreferencesState, iconState: MenuBarIconState) {
        self.daemon = daemon
        self.preferences = preferences
        self.iconState = iconState
        _minutes = State(initialValue: preferences.defaultMinutes)
    }

    private var maxMinutes: Int { daemon.policy?.maxMinutes ?? 60 }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            header
            serverLine
            Divider()
            if daemon.serviceStatus != .enabled {
                serviceMissing
            } else if daemon.pendingRequest != nil {
                pendingSection
            } else if daemon.isAdmin {
                adminSection
            } else {
                elevateSection
            }
            Divider()
            footer
        }
        .padding(14)
        .frame(width: 300)
        .overlay {
            if daemon.busy {
                ZStack {
                    Color.black.opacity(0.6)
                    ProgressView()
                }
            }
        }
        .onAppear {
            if preferences.resetDefaultTime {
                minutes = preferences.defaultMinutes
            }
            Task { await daemon.refreshStatus() }
        }
    }

    private var header: some View {
        HStack {
            Text("Micromanage").font(.title2).bold()
            Spacer()
            SettingsLink {
                Image(systemName: "gear")
            }
            .buttonStyle(.plain)
            .help("Settings")
        }
    }

    @ViewBuilder
    private var serverLine: some View {
        if let server = daemon.server, server.configured {
            VStack(alignment: .leading, spacing: 2) {
                Text("Managed by \(server.tenantID ?? "your organization")").font(.caption)
                Text("Last check-in \(relativeTime(server.lastCheckIn))")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                if let error = server.lastError, !error.isEmpty {
                    Text(error).font(.caption2).foregroundStyle(.red).lineLimit(2)
                }
            }
        } else {
            Text("Local mode, no management server").font(.caption).foregroundStyle(.secondary)
        }
    }

    private var serviceMissing: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("The background service is not running.")
            Button("Set it up") {
                Task { await daemon.registerDaemon() }
            }
        }
    }

    private var pendingSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                ProgressView().controlSize(.small)
                Text("Waiting for an administrator to approve")
            }
            if let pending = daemon.pendingRequest {
                Text("\(minutesText(pending.seconds)) requested \(relativeTime(pending.requestedAt))")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private var adminSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Gauge(value: Double(daemon.timeRemaining), in: 0...Double(max(daemon.timeSet, 1))) {
                Text("Time remaining: \(minutesText(daemon.timeRemaining))")
            }
            DisclosureGroup("Add time", isExpanded: $showAddTime) {
                HStack {
                    Stepper(value: $extraMinutes, in: 1...max(1, maxMinutes)) {
                        TextField("min", value: $extraMinutes, format: .number).frame(width: 50)
                    }
                    Button("Set to \(newTotalMinutes) min") {
                        daemon.requestAdmin(minutes: newTotalMinutes, reason: reason)
                    }
                    .disabled(daemon.busy)
                }
            }
            Button("Demote now") {
                daemon.demoteNow()
            }
            .keyboardShortcut(.defaultAction)
            .disabled(daemon.busy)
        }
    }

    private var newTotalMinutes: Int {
        min(maxMinutes, extraMinutes + Int((Double(daemon.timeRemaining) / 60).rounded(.up)))
    }

    private var elevateSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            if let policy = daemon.policy, !policy.enabled {
                Text("Admin elevation is turned off by policy.").foregroundStyle(.secondary)
            } else {
                HStack {
                    Stepper(value: $minutes, in: 1...max(1, maxMinutes)) {
                        TextField("Minutes", value: $minutes, format: .number).frame(width: 50)
                    }
                    Text("min")
                    Spacer()
                    Button("Elevate") {
                        daemon.requestAdmin(minutes: min(minutes, maxMinutes), reason: reason)
                    }
                    .keyboardShortcut(.defaultAction)
                    .disabled(daemon.busy)
                }
                if daemon.policy?.requireApproval ?? false {
                    TextField("Reason for the request", text: $reason)
                    Text("An administrator approves each request.")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
            }
        }
    }

    private var footer: some View {
        HStack {
            if daemon.isAdmin {
                Text("You are an administrator").foregroundStyle(.red)
            } else {
                Text("You are a standard user").foregroundStyle(.green)
            }
            Spacer()
            Text("v\(Bundle.main.appVersion)").foregroundStyle(.secondary)
        }
        .font(.caption)
    }
}
