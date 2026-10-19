//
//  AdminGrants.swift
//  micromanaged
//
//  Created by Liem Eldert on 2026/10/05.
//

import Darwin
import Foundation
import os

nonisolated enum AdminError: Error, CustomStringConvertible {
    case notRoot
    case invalidUser(String)
    case systemAccount(String)
    case commandFailed(String)

    var description: String {
        switch self {
        case .notRoot:
            return "The daemon must run as root."
        case .invalidUser(let name):
            return "\(name) is not a local user account."
        case .systemAccount(let name):
            return "\(name) is a system account and cannot be elevated."
        case .commandFailed(let detail):
            return detail
        }
    }
}

nonisolated struct LocalUser: Sendable {
    var name: String
    var uid: uid_t

    static let usernamePattern = try! NSRegularExpression(pattern: "^[A-Za-z0-9._-]{1,64}$")

    static func lookup(uid: uid_t) -> LocalUser? {
        guard let entry = getpwuid(uid) else {
            return nil
        }
        return LocalUser(name: String(cString: entry.pointee.pw_name), uid: entry.pointee.pw_uid)
    }

    static func lookup(name: String) throws -> LocalUser {
        let range = NSRange(name.startIndex..., in: name)
        guard usernamePattern.firstMatch(in: name, range: range) != nil else {
            throw AdminError.invalidUser(name)
        }
        guard let entry = getpwnam(name) else {
            throw AdminError.invalidUser(name)
        }
        let user = LocalUser(name: String(cString: entry.pointee.pw_name), uid: entry.pointee.pw_uid)
        try user.requireElevatable()
        return user
    }

    func requireElevatable() throws {
        if uid < 500 {
            throw AdminError.systemAccount(name)
        }
    }
}

// admin membership which gets granted for a specific period
actor AdminGrants {
    private static let dseditgroup = "/usr/sbin/dseditgroup"

    private let state: AgentState
    private var timers: [String: Task<Void, Never>] = [:]
    private var sweeper: Task<Void, Never>?
    private var eventSink: (@Sendable (String, String?, [String: String]) async -> Void)?

    init(state: AgentState) {
        self.state = state
    }

    func setEventSink(_ sink: @escaping @Sendable (String, String?, [String: String]) async -> Void) {
        eventSink = sink
    }

    // Revokes grants that expired while the daemon was down and reschedules the rest.
    func restore() async {
        let saved = await state.grants
        for grant in saved {
            if grant.expiresAt <= Date() {
                await revoke(username: grant.username, reason: "expired while the daemon was not running")
            } else {
                schedule(grant)
            }
        }
        sweeper?.cancel()
        sweeper = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(30))
                await self?.expireDue()
            }
        }
    }

    func currentGrant(for username: String) async -> AdminGrant? {
        await state.grants.first { $0.username == username }
    }

    func allGrants() async -> [AdminGrant] {
        await state.grants
    }

    static func isAdmin(_ username: String) -> Bool {
        let args = ["-o", "checkmember", "-m", username, "admin"]
        guard let result = try? Shell.run(dseditgroup, args, timeout: 15) else {
            return false
        }
        return result.ok
    }

    func grant(user: LocalUser, seconds: Int, reason: String?, source: String) async throws -> AdminGrant {
        guard DaemonInfo.isRoot else {
            throw AdminError.notRoot
        }
        try user.requireElevatable()
        let result = try Shell.run(AdminGrants.dseditgroup, ["-o", "edit", "-a", user.name, "-t", "user", "admin"],
                                   timeout: 30)
        guard result.ok else {
            throw AdminError.commandFailed("dseditgroup exited \(result.status): \(result.output)")
        }
        guard AdminGrants.isAdmin(user.name) else {
            throw AdminError.commandFailed("\(user.name) is still not a member of admin after the change")
        }
        let now = Date()
        let grant = AdminGrant(id: UUID().uuidString, username: user.name, uid: user.uid, grantedAt: now,
                               expiresAt: now.addingTimeInterval(TimeInterval(seconds)), source: source, reason: reason)
        var grants = await state.grants.filter { $0.username != user.name }
        grants.append(grant)
        await state.setGrants(grants)
        schedule(grant)
        logger.info("granted admin to \(user.name, privacy: .public) for \(seconds)s (\(source, privacy: .public))")
        await emit("admin.granted", user.name, ["seconds": String(seconds), "source": source, "reason": reason ?? "",
                                                 "grant_id": grant.id])
        return grant
    }

    // Removes the user from the admin group, retrying up to three times because directory service calls fail
    // intermittently.
    @discardableResult
    func revoke(username: String, reason: String) async -> Bool {
        timers[username]?.cancel()
        timers[username] = nil
        let grant = await currentGrant(for: username)
        var lastOutput = ""
        var removed = false
        for attempt in 1...3 {
            if !AdminGrants.isAdmin(username) {
                removed = true
                break
            }
            guard DaemonInfo.isRoot else {
                lastOutput = AdminError.notRoot.description
                break
            }
            if let result = try? Shell.run(AdminGrants.dseditgroup,
                                           ["-o", "edit", "-d", username, "-t", "user", "admin"], timeout: 30) {
                lastOutput = result.output
                if result.ok && !AdminGrants.isAdmin(username) {
                    removed = true
                    break
                }
            }
            let failure = "attempt \(attempt): \(lastOutput)"
            logger.warning("revoking admin from \(username, privacy: .public) failed, \(failure, privacy: .public)")
            try? await Task.sleep(for: .seconds(2))
        }
        if removed {
            let remaining = await state.grants.filter { $0.username != username }
            await state.setGrants(remaining)
            logger.info("revoked admin from \(username, privacy: .public): \(reason, privacy: .public)")
            await emit("admin.revoked", username, ["reason": reason, "grant_id": grant?.id ?? ""])
        } else {
            logger.error("could not revoke admin from \(username, privacy: .public): \(lastOutput, privacy: .public)")
            await emit("admin.revoke_failed", username, ["reason": reason, "detail": lastOutput])
        }
        return removed
    }

    private func schedule(_ grant: AdminGrant) {
        timers[grant.username]?.cancel()
        let delay = max(0, grant.expiresAt.timeIntervalSinceNow)
        let username = grant.username
        timers[username] = Task { [weak self] in
            try? await Task.sleep(for: .seconds(delay))
            guard !Task.isCancelled else {
                return
            }
            await self?.revoke(username: username, reason: "the grant expired")
        }
    }

    private func expireDue() async {
        let now = Date()
        for grant in await state.grants where grant.expiresAt <= now {
            await revoke(username: grant.username, reason: "the grant expired")
        }
    }

    private func emit(_ kind: String, _ username: String?, _ detail: [String: String]) async {
        await state.appendEvent(kind: kind, username: username, detail: detail)
        if let eventSink {
            await eventSink(kind, username, detail)
        }
    }
}
