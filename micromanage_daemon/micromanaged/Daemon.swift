//
//  Daemon.swift
//  micromanaged
//
//  Created by Liem Eldert on 2026/10/05.
//

import Darwin
import Foundation
import os

let logger = Logger(subsystem: MicromanageIdentity.daemonIdentifier, category: "daemon")

nonisolated enum DaemonInfo {
    static let startedAt = Date()

    static var version: String {
        Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "unknown"
    }

    static var isRoot: Bool { getuid() == 0 }
}

final class MicromanageDaemon {
    private let state: AgentState
    private let grants: AdminGrants
    private let coordinator: Coordinator
    private let service: DaemonService

    init() {
        let state = AgentState()
        let grants = AdminGrants(state: state)
        let coordinator = Coordinator(state: state, grants: grants)
        self.state = state
        self.grants = grants
        self.coordinator = coordinator
        self.service = DaemonService(coordinator: coordinator, grants: grants)
    }

    func start() {
        logger.info("micromanaged \(DaemonInfo.version, privacy: .public) starting as uid \(getuid())")
        if !DaemonInfo.isRoot {
            // A Debug run from the IDE. Operations that edit the admin group or install packages are refused; the XPC
            // surface, facts and server traffic still work.
            logger.warning("not running as root; privileged operations will be refused")
        }
        let grants = self.grants
        let coordinator = self.coordinator
        Task {
            await grants.restore()
            await coordinator.run()
        }
        service.start()
    }
}
