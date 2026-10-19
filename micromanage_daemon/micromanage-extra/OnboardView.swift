//
//  OnboardView.swift
//  micromanage-extra
//
//  Created by Liem Eldert on 2026/10/05.
//

import ServiceManagement
import SwiftUI

// Shown while the launchd job waits for approval under Login Items. A management profile that pre-approves the team
// skips this entirely.
struct DaemonOnboardView: View {
    @ObservedObject var daemon: DaemonClient
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Micromanage").font(.title)
            Divider()
            Text("""
            Micromanage needs permission to run its background service.

                1. Open System Settings.
                2. Go to General, then Login Items & Extensions.
                3. Under "Allow in the Background", turn on Micromanage.

            This window closes on its own once the service is allowed.
            """)
            Spacer()
            HStack {
                Button("Open Login Items") {
                    SMAppService.openSystemSettingsLoginItems()
                }
                Button("Check again") {
                    Task { await daemon.registerDaemon() }
                }
                Spacer()
                Button("Close") {
                    dismiss()
                }
            }
        }
        .padding(20)
        .frame(width: 460, height: 300)
        .alwaysOnTop()
        .onChange(of: daemon.needsApproval) { _, needs in
            if !needs {
                dismiss()
            }
        }
    }
}

struct UserOnboardView: View {
    @ObservedObject var preferences: PreferencesState
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Micromanage").font(.title)
            Divider()
            Text("""
            Your account is a standard user. When you need administrator access:

                1. Click the shield in the menu bar.
                2. Choose how long you need and click Elevate.
                3. Authenticate when macOS asks.
                4. Open a new Terminal window if you need sudo.

            Access ends by itself when the time runs out, and you can end it early from the same menu. Your account \
            name is \(NSUserName()).
            """)
            Spacer()
            HStack {
                Spacer()
                Button("Close") {
                    preferences.firstLaunch = false
                    dismiss()
                }
                .keyboardShortcut(.defaultAction)
            }
        }
        .padding(20)
        .frame(width: 460, height: 320)
        .alwaysOnTop()
    }
}
