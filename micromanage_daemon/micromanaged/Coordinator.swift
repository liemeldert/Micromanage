//
//  Coordinator.swift
//  micromanaged
//
//  Created by Liem Eldert on 2026/10/05.
//

import Foundation
import os

// Polls remote server and XPC service
actor Coordinator {
    static let pollWithoutServer: Duration = .seconds(60)
    static let factsResendHours: TimeInterval = 6

    private let state: AgentState
    private let grants: AdminGrants
    private let client = ServerClient()
    private var sleeper: Task<Void, Error>?
    private var consecutiveFailures = 0
    private var forceFacts = false
    private var running = false

    init(state: AgentState, grants: AdminGrants) {
        self.state = state
        self.grants = grants
    }

    // MARK: - Loop

    func run() async {
        guard !running else {
            return
        }
        running = true
        await grants.setEventSink { [weak self] _, _, _ in
            await self?.wake()
        }
        while true {
            let config = Configuration.load()
            var delay = Coordinator.pollWithoutServer
            if config.serverMode {
                do {
                    try await enrollIfNeeded(config)
                    if let credential = await state.credential {
                        try await heartbeat(config, credential: credential)
                        consecutiveFailures = 0
                        delay = await heartbeatDelay(config)
                    }
                } catch {
                    consecutiveFailures += 1
                    let message = String(describing: error)
                    logger.error("server round failed: \(message, privacy: .public)")
                    await state.update { $0.lastError = message }
                    delay = backoff()
                }
            }
            await sleep(delay)
        }
    }

    func wake() {
        sleeper?.cancel()
    }

    private func sleep(_ duration: Duration) async {
        let task = Task { try await Task.sleep(for: duration) }
        sleeper = task
        _ = await task.result
        sleeper = nil
    }

    // Apply jitter onto heartbeat
    private func heartbeatDelay(_ config: Configuration) async -> Duration {
        let minutes = await state.state.heartbeatMinutes ?? config.heartbeatMinutes
        let base = Double(min(max(minutes, 1), 1440) * 60)
        let jitter = Double.random(in: 0...(base * 0.1))
        return .seconds(base + jitter)
    }

    private func backoff() -> Duration {
        let seconds = min(60.0 * pow(2.0, Double(min(consecutiveFailures, 6))), 30 * 60)
        return .seconds(seconds)
    }

    // MARK: enrollment and heartbeat

    private func enrollIfNeeded(_ config: Configuration) async throws {
        guard await state.credential == nil, let serverURL = config.serverURL else {
            return
        }
        guard let code = config.enrollmentCode, !code.isEmpty else {
            logger.info("no enrollment code in the managed preferences yet")
            return
        }
        let system = FactsCollector.system()
        let request = EnrollRequest(code: code,
                                    serialNumber: system["serial_number"] as? String,
                                    hardwareUuid: system["hardware_uuid"] as? String,
                                    hostname: system["computer_name"] as? String,
                                    agentVersion: DaemonInfo.version)
        let response = try await client.enroll(serverURL: serverURL, request: request)
        let credential = Credential(token: response.token, deviceID: response.deviceId, tenantID: response.tenantId,
                                    serverURL: serverURL.absoluteString, enrolledAt: Date())
        await state.setCredential(credential)
        await state.update { state in
            state.lastError = nil
            state.heartbeatMinutes = response.heartbeatMinutes
        }
        let deviceID = response.deviceId
        let tenantID = response.tenantId
        logger.info("enrolled as device \(deviceID, privacy: .public) in tenant \(tenantID, privacy: .public)")
    }

    private func heartbeat(_ config: Configuration, credential: Credential) async throws {
        let snapshot = await state.state
        var factsValue: JSONValue?
        var digest = snapshot.factsDigest
        if config.factsEnabled {
            let report = await Task.detached(priority: .utility) { FactsCollector.report() }.value
            let stale = snapshot.factsSentAt.map {
                Date().timeIntervalSince($0) > Coordinator.factsResendHours * 3600
            } ?? true
            if forceFacts || report.digest != snapshot.factsDigest || stale {
                factsValue = report.value
                digest = report.digest
            }
        }
        let events = snapshot.events
        let activeGrants = await grants.allGrants().map(\.info)
        let request = HeartbeatRequest(agentVersion: DaemonInfo.version, facts: factsValue, factsDigest: digest,
                                       events: events, pendingRequestIds: snapshot.pendingRequests.map(\.requestID),
                                       grants: activeGrants)
        let response: HeartbeatResponse
        do {
            response = try await client.heartbeat(credential: credential, request: request)
        } catch ServerError.unauthorized {
            // The server rejected the credential. Clear it so a new enrollment code can be used.
            logger.error("the server refused the device credential; a new enrollment code is needed")
            await state.setCredential(nil)
            throw ServerError.unauthorized
        }
        forceFacts = response.factsWanted ?? false
        await state.removeEvents(ids: Set(events.map(\.id)))
        await state.update { state in
            state.lastCheckIn = Date()
            state.lastError = nil
            if factsValue != nil {
                state.factsDigest = digest
                state.factsSentAt = Date()
            }
            if let minutes = response.heartbeatMinutes {
                state.heartbeatMinutes = min(max(minutes, 1), 1440)
            }
            if let policy = response.policy?.admin {
                state.adminPolicy = policy
            }
        }
        if let token = response.rotateToken, !token.isEmpty {
            var rotated = credential
            rotated.token = token
            await state.setCredential(rotated)
        }
        await applyDecisions(response.jitDecisions ?? [], config: config)
        await runTasks(response.tasks ?? [], config: config, credential: credential)
    }

    private func applyDecisions(_ decisions: [JITDecision], config: Configuration) async {
        guard !decisions.isEmpty else {
            return
        }
        let pending = await state.state.pendingRequests
        let policy = await effectivePolicy(config)
        for decision in decisions {
            guard let request = pending.first(where: { $0.requestID == decision.requestId }) else {
                continue
            }
            let requestID = decision.requestId
            await state.update { state in
                state.pendingRequests.removeAll { $0.requestID == requestID }
            }
            if decision.decision == "approved" {
                let seconds = min((decision.minutes ?? request.seconds / 60) * 60, policy.maxMinutes * 60)
                do {
                    let user = try LocalUser.lookup(name: request.username)
                    _ = try await grants.grant(user: user, seconds: max(seconds, 60), reason: request.reason,
                                               source: "approved by \(decision.decidedBy ?? "an admin")")
                } catch {
                    let detail = String(describing: error)
                    logger.error("approved request \(requestID, privacy: .public) failed: \(detail, privacy: .public)")
                    await state.appendEvent(kind: "admin.grant_failed", username: request.username,
                                            detail: ["request_id": requestID, "error": detail])
                }
            } else {
                await state.appendEvent(kind: "admin.denied", username: request.username,
                                        detail: ["request_id": requestID, "decided_by": decision.decidedBy ?? ""])
            }
        }
    }

    private func runTasks(_ tasks: [AgentTask], config: Configuration, credential: Credential) async {
        guard !tasks.isEmpty else {
            return
        }
        let context = TaskContext(config: config, policy: await effectivePolicy(config),
                                  downloadsDirectory: await state.downloadsDirectory)
        let session = client.session
        for task in tasks {
            logger.info("running task \(task.id, privacy: .public) (\(task.type, privacy: .public))")
            let result = await TaskRunner.run(task, context: context, grants: grants, session: session)
            if task.type == "collect_facts" {
                forceFacts = true
            }
            do {
                try await client.postResult(credential: credential, taskID: task.id, result: result)
            } catch {
                let detail = String(describing: error)
                logger.error("could not report task \(task.id, privacy: .public): \(detail, privacy: .public)")
            }
        }
        if forceFacts {
            wake()
        }
    }

    // MARK: XPC

    // The policy with the server's overrides applied.
    func effectivePolicy(_ config: Configuration) async -> AdminPolicy {
        var policy = config.adminPolicy
        if config.serverMode, let override = await state.state.adminPolicy {
            policy.enabled = override.enabled ?? policy.enabled
            policy.maxMinutes = override.maxMinutes ?? policy.maxMinutes
            policy.defaultMinutes = override.defaultMinutes ?? policy.defaultMinutes
            policy.requireApproval = override.requireApproval ?? policy.requireApproval
            policy.requireAuthentication = override.requireAuthentication ?? policy.requireAuthentication
            policy.defaultMinutes = min(policy.defaultMinutes, policy.maxMinutes)
        }
        return policy
    }

    func serverStatus(_ config: Configuration) async -> ServerStatus {
        let credential = await state.credential
        let snapshot = await state.state
        return ServerStatus(configured: config.serverMode, enrolled: credential != nil,
                            tenantID: credential?.tenantID ?? config.tenantID,
                            serverURL: config.serverURL?.absoluteString, deviceID: credential?.deviceID,
                            lastCheckIn: snapshot.lastCheckIn, lastError: snapshot.lastError)
    }

    func status(for user: LocalUser) async -> DaemonStatus {
        let config = Configuration.load()
        let grant = await grants.currentGrant(for: user.name)
        let pending = await state.state.pendingRequests.first { $0.username == user.name }
        let policy = await effectivePolicy(config)
        return DaemonStatus(daemonVersion: DaemonInfo.version, username: user.name,
                            isAdmin: AdminGrants.isAdmin(user.name), grant: grant?.info, pendingRequest: pending?.info,
                            policy: policy.info, server: await serverStatus(config))
    }

    func requestAdmin(user: LocalUser, seconds requested: Int, reason: String,
                      authenticated: Bool) async -> AdminRequestResult {
        let config = Configuration.load()
        let policy = await effectivePolicy(config)
        do {
            try user.requireElevatable()
        } catch {
            return .denied(String(describing: error))
        }
        if let refusal = policy.refusal(for: user.name) {
            return .denied(refusal)
        }
        if policy.requireAuthentication && !authenticated {
            return .denied("Authentication is required before elevating.")
        }
        let seconds = min(max(requested, 60), policy.maxMinutes * 60)
        let trimmedReason = reason.trimmingCharacters(in: .whitespacesAndNewlines)
        let note = trimmedReason.isEmpty ? nil : String(trimmedReason.prefix(500))

        guard config.serverMode && policy.requireApproval else {
            let source = config.serverMode ? "self-service" : "local"
            return await grantNow(user: user, seconds: seconds, reason: note, source: source)
        }
        guard let credential = await state.credential else {
            return .denied("This Mac is not enrolled with the server yet, so approval cannot be requested.")
        }
        if let pending = await state.state.pendingRequests.first(where: { $0.username == user.name }) {
            return AdminRequestResult(outcome: .pending, message: "A request is already waiting for approval.",
                                      grant: nil, requestID: pending.requestID)
        }
        let response: JITResponse
        do {
            let request = JITRequest(username: user.name, minutes: seconds / 60, reason: note)
            response = try await client.requestJIT(credential: credential, request: request)
        } catch {
            return AdminRequestResult(outcome: .failed, message: "The server could not be reached: \(error)",
                                      grant: nil, requestID: nil)
        }
        switch response.decision {
        case "approved":
            let granted = min((response.minutes ?? seconds / 60) * 60, seconds)
            return await grantNow(user: user, seconds: max(granted, 60), reason: note, source: "approved by policy")
        case "pending":
            let pending = PendingAdminRequest(requestID: response.id, username: user.name, uid: user.uid,
                                              seconds: seconds, reason: note, requestedAt: Date())
            await state.update { $0.pendingRequests.append(pending) }
            await state.appendEvent(kind: "admin.requested", username: user.name,
                                    detail: ["request_id": response.id, "seconds": String(seconds),
                                             "reason": note ?? ""])
            wake()
            return AdminRequestResult(outcome: .pending, message: "Waiting for an administrator to approve...",
                                      grant: nil, requestID: response.id)
        default:
            await state.appendEvent(kind: "admin.denied", username: user.name,
                                    detail: ["request_id": response.id, "reason": note ?? ""])
            return AdminRequestResult(outcome: .denied, message: "The request was declined.", grant: nil,
                                      requestID: response.id)
        }
    }

    private func grantNow(user: LocalUser, seconds: Int, reason: String?, source: String) async -> AdminRequestResult {
        do {
            let grant = try await grants.grant(user: user, seconds: seconds, reason: reason, source: source)
            return AdminRequestResult(outcome: .granted, message: nil, grant: grant.info, requestID: nil)
        } catch {
            return AdminRequestResult(outcome: .failed, message: String(describing: error), grant: nil, requestID: nil)
        }
    }

    func revokeAdmin(user: LocalUser) async -> SimpleResult {
        let removed = await grants.revoke(username: user.name, reason: "demoted by the user")
        return SimpleResult(ok: removed, message: removed ? nil : "Admin membership could not be removed.")
    }

    func checkInNow() async -> SimpleResult {
        let config = Configuration.load()
        guard config.serverMode else {
            return SimpleResult(ok: false, message: "No server is configured.")
        }
        do {
            try await enrollIfNeeded(config)
            guard let credential = await state.credential else {
                return SimpleResult(ok: false, message: "Not yet enrolled. Waiting for an enrollment code.")
            }
            forceFacts = true
            try await heartbeat(config, credential: credential)
            consecutiveFailures = 0
            return SimpleResult(ok: true, message: nil)
        } catch {
            let message = String(describing: error)
            await state.update { $0.lastError = message }
            return SimpleResult(ok: false, message: message)
        }
    }
}

private extension AdminRequestResult {
    static func denied(_ message: String) -> AdminRequestResult {
        AdminRequestResult(outcome: .denied, message: message, grant: nil, requestID: nil)
    }
}
