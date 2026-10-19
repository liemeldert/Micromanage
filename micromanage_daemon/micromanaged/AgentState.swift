//
//  AgentState.swift
//  micromanaged
//
//  Created by Liem Eldert on 2026/10/05.
//

import Darwin
import Foundation
import os

nonisolated struct Credential: Codable, Sendable {
    var token: String
    var deviceID: String
    var tenantID: String
    var serverURL: String
    var enrolledAt: Date
}

nonisolated struct AdminGrant: Codable, Sendable {
    var id: String
    var username: String
    var uid: UInt32
    var grantedAt: Date
    var expiresAt: Date
    var source: String
    var reason: String?

    var info: AdminGrantInfo {
        AdminGrantInfo(username: username, grantedAt: grantedAt, expiresAt: expiresAt, source: source, reason: reason)
    }
}

nonisolated struct PendingAdminRequest: Codable, Sendable {
    var requestID: String
    var username: String
    var uid: UInt32
    var seconds: Int
    var reason: String?
    var requestedAt: Date

    var info: PendingRequestInfo {
        PendingRequestInfo(requestID: requestID, username: username, seconds: seconds, requestedAt: requestedAt)
    }
}

nonisolated struct AgentEvent: Codable, Sendable {
    var id: String
    var kind: String
    var at: Date
    var username: String?
    var detail: [String: String]
}

nonisolated struct ServerAdminPolicy: Codable, Sendable {
    var enabled: Bool?
    var maxMinutes: Int?
    var defaultMinutes: Int?
    var requireApproval: Bool?
    var requireAuthentication: Bool?
}

nonisolated struct PersistedState: Codable, Sendable {
    var lastCheckIn: Date?
    var lastError: String?
    var factsDigest: String?
    var factsSentAt: Date?
    var heartbeatMinutes: Int?
    var events: [AgentEvent] = []
    var pendingRequests: [PendingAdminRequest] = []
    var adminPolicy: ServerAdminPolicy?
}

actor AgentState {
    static let maxEvents = 200

    let directory: URL
    private(set) var credential: Credential?
    private(set) var grants: [AdminGrant]
    private(set) var state: PersistedState

    init() {
        let base: URL
        if DaemonInfo.isRoot {
            base = URL(fileURLWithPath: MicromanageIdentity.stateDirectory, isDirectory: true)
        } else {
            base = FileManager.default.homeDirectoryForCurrentUser
                .appending(path: "Library/Application Support/Micromanage", directoryHint: .isDirectory)
        }
        directory = base
        AgentState.ensureDirectory(base)
        credential = AgentState.read(Credential.self, at: base.appending(path: "credential.json"))
        grants = AgentState.read([AdminGrant].self, at: base.appending(path: "grants.json")) ?? []
        state = AgentState.read(PersistedState.self, at: base.appending(path: "state.json")) ?? PersistedState()
    }

    var downloadsDirectory: URL {
        let url = directory.appending(path: "downloads", directoryHint: .isDirectory)
        AgentState.ensureDirectory(url)
        return url
    }

    func setCredential(_ value: Credential?) {
        credential = value
        if let value {
            write(value, to: "credential.json")
        } else {
            try? FileManager.default.removeItem(at: directory.appending(path: "credential.json"))
        }
    }

    func setGrants(_ value: [AdminGrant]) {
        grants = value
        write(value, to: "grants.json")
    }

    func update(_ change: (inout PersistedState) -> Void) {
        change(&state)
        write(state, to: "state.json")
    }

    func appendEvent(kind: String, username: String?, detail: [String: String]) {
        let event = AgentEvent(id: UUID().uuidString, kind: kind, at: Date(), username: username, detail: detail)
        update { state in
            state.events.append(event)
            if state.events.count > AgentState.maxEvents {
                state.events.removeFirst(state.events.count - AgentState.maxEvents)
            }
        }
    }

    func removeEvents(ids: Set<String>) {
        update { state in
            state.events.removeAll { ids.contains($0.id) }
        }
    }

    private func write<T: Encodable>(_ value: T, to name: String) {
        let url = directory.appending(path: name)
        do {
            let data = try JSONCoding.encoder().encode(value)
            try data.write(to: url, options: .atomic)
            chmod(url.path, 0o600)
        } catch {
            logger.error("could not write \(name, privacy: .public): \(error.localizedDescription, privacy: .public)")
        }
    }

    private static func read<T: Decodable>(_ type: T.Type, at url: URL) -> T? {
        guard let data = FileManager.default.contents(atPath: url.path) else {
            return nil
        }
        do {
            return try JSONCoding.decode(type, from: data)
        } catch {
            let name = url.lastPathComponent
            logger.error("could not read \(name, privacy: .public): \(error.localizedDescription, privacy: .public)")
            return nil
        }
    }

    private static func ensureDirectory(_ url: URL) {
        do {
            try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true,
                                                    attributes: [.posixPermissions: 0o700])
        } catch {
            let path = url.path
            logger.error("could not create \(path, privacy: .public): \(error.localizedDescription, privacy: .public)")
        }
    }
}
