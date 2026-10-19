//
//  micromanage_extraApp.swift
//  micromanage-extra
//
//  Created by Liem Eldert on 2026/10/05.
//

import AppKit
import SwiftUI

@main
struct micromanage_extraApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @Environment(\.openWindow) private var openWindow
    @ObservedObject private var daemon = DaemonClient.shared
    @ObservedObject private var preferences = PreferencesState.shared
    @ObservedObject private var iconState = MenuBarIconState.shared

    var body: some Scene {
        MenuBarExtra("Micromanage", systemImage: iconState.symbolName) {
            ContentView(daemon: daemon, preferences: preferences, iconState: iconState)
        }
        .menuBarExtraStyle(.window)
        .onChange(of: daemon.needsApproval) { _, needs in
            if needs {
                openWindow(id: WindowID.daemonOnboard)
            }
        }
        .onChange(of: preferences.firstLaunch, initial: true) { _, first in
            if first {
                openWindow(id: WindowID.firstLaunch)
            }
        }
        Settings {
            SettingsView(daemon: daemon, preferences: preferences)
        }
        Window("Micromanage", id: WindowID.daemonOnboard) {
            DaemonOnboardView(daemon: daemon)
        }
        .windowResizability(.contentSize)
        Window("Welcome to Micromanage", id: WindowID.firstLaunch) {
            UserOnboardView(preferences: preferences)
        }
        .windowResizability(.contentSize)
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        DaemonClient.shared.startupTasks()
    }
}
