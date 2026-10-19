//
//  DaemonClient.swift
//  micromanage-extra
//
//  Created by Liem Eldert on 2026/10/05.
//

import AppKit
import Combine
import Foundation
import LocalAuthentication
import ServiceManagement
import UserNotifications
import os

enum DaemonClientError: Error, CustomStringConvertible {
    case noProxy
    case timeout

    var description: String {
        switch self {
        case .noProxy:
            return "the background service connection could not be set up"
        case .timeout:
            return "the background service did not answer in time"
        }
    }
}

// Resumes the continuation only once, whichever call comes first.
nonisolated private final class ResumeOnce<T: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<T, Error>?

    init(_ continuation: CheckedContinuation<T, Error>) {
        self.continuation = continuation
    }

    func resume(_ result: Result<T, Error>) {
        lock.lock()
        let pending = continuation
        continuation = nil
        lock.unlock()
        pending?.resume(with: result)
    }
}

final class DaemonClient: ObservableObject {
    static let shared = DaemonClient()
    static let pollInterval: Duration = .seconds(15)
    static let callTimeout: Duration = .seconds(20)
    static let longCallTimeout: Duration = .seconds(60)

    @Published var status: DaemonStatus?
    @Published var serviceStatus: SMAppService.Status = .notRegistered
    @Published var needsApproval = false
    @Published var busy = false
    @Published var timeRemaining = 0
    @Published var timeSet = 0
    @Published var connectionFailures = 0
    @Published var facts: String?

    let alert = AlertController()
    private var connection: NSXPCConnection?
    private var countdown: Task<Void, Never>?
    private var poller: Task<Void, Never>?
    private var warned = false

    var isAdmin: Bool { status?.isAdmin ?? false }
    var grant: AdminGrantInfo? { status?.grant }
    var pendingRequest: PendingRequestInfo? { status?.pendingRequest }
    var policy: AdminPolicyInfo? { status?.policy }
    var server: ServerStatus? { status?.server }
    var daemonVersion: String { status?.daemonVersion ?? "unknown" }

    // MARK: Startup

    func startupTasks() {
        if !isDebuggerAttached() && !Bundle.main.installedInApplications {
            alert.show("Micromanage Sensor has to be installed in /Applications to function. Please move it there, reinstall, or contact your administrator!")
        }
        refreshServiceStatus()
        if serviceStatus == .enabled {
            startPolling()
        } else {
            Task { await registerDaemon() }
        }
        registerLoginItem()
    }

    func refreshServiceStatus() {
        serviceStatus = SMAppService.daemon(plistName: MicromanageIdentity.daemonPlistName).status
    }

    // Registers the launchd job carried inside the app bundle. On a Mac without a management profile that pre-approves
    // it, the user has to allow it under Login Items, and this waits for that.
    func registerDaemon() async {
        let service = SMAppService.daemon(plistName: MicromanageIdentity.daemonPlistName)
        do {
            try service.register()
        } catch {
            logger.error("daemon registration failed: \(error.localizedDescription, privacy: .public)")
            if service.status != .requiresApproval {
                alert.show("The background service could not be registered: \(error.localizedDescription)")
            }
        }
        await settle(service)
    }

    private func settle(_ service: SMAppService) async {
        serviceStatus = service.status
        switch service.status {
        case .enabled:
            needsApproval = false
            startPolling()
        case .requiresApproval:
            needsApproval = true
            SMAppService.openSystemSettingsLoginItems()
            for _ in 0..<150 {
                try? await Task.sleep(for: .seconds(2))
                if service.status == .enabled {
                    needsApproval = false
                    serviceStatus = .enabled
                    startPolling()
                    return
                }
            }
        case .notFound:
            alert.show("The background service is missing from the sensor app bundle. Contact your administrator!")
        case .notRegistered:
            alert.show("The background service is not registered.")
        @unknown default:
            alert.show("The background service reports a state this version does not know.")
        }
    }

    func unregisterDaemon() {
        let service = SMAppService.daemon(plistName: MicromanageIdentity.daemonPlistName)
        do {
            try service.unregister()
        } catch {
            alert.show("The background service could not be unregistered: \(error.localizedDescription)")
        }
        stopPolling()
        connection?.invalidate()
        connection = nil
        serviceStatus = service.status
        status = nil
    }

    private func registerLoginItem() {
        guard !isDebuggerAttached() else {
            return
        }
        let app = SMAppService.mainApp
        guard app.status != .enabled else {
            return
        }
        do {
            try app.register()
        } catch {
            logger.error("login item registration failed: \(error.localizedDescription, privacy: .public)")
        }
    }

    // MARK: - Status

    private func startPolling() {
        guard poller == nil else {
            return
        }
        poller = Task { [weak self] in
            while !Task.isCancelled {
                guard let self else {
                    return
                }
                await self.refreshStatus()
                try? await Task.sleep(for: DaemonClient.pollInterval)
            }
        }
    }

    private func stopPolling() {
        poller?.cancel()
        poller = nil
    }

    func refreshStatus() async {
        do {
            let fresh: DaemonStatus = try await call(timeout: DaemonClient.callTimeout) { service, reply in
                service.status(reply: reply)
            }
            connectionFailures = 0
            apply(fresh)
        } catch {
            connectionFailures += 1
            let detail = String(describing: error)
            logger.error("status call failed (\(self.connectionFailures)): \(detail, privacy: .public)")
            if connectionFailures == 3 {
                alert.show("The background service has stopped responding. Try restarting the Mac, then contact your administrator if this continues.")
            }
        }
    }

    private func apply(_ fresh: DaemonStatus) {
        status = fresh
        MenuBarIconState.shared.update(isAdmin: fresh.isAdmin, pending: fresh.pendingRequest != nil)
        if let grant = fresh.grant {
            timeSet = grant.totalSeconds
            timeRemaining = grant.secondsRemaining
            startCountdown()
        } else {
            timeRemaining = 0
            timeSet = 0
            stopCountdown()
        }
    }

    // MARK:Admin

    func requestAdmin(minutes: Int, reason: String) {
        guard !busy else {
            return
        }
        let seconds = max(1, minutes) * 60
        busy = true
        Task {
            defer { busy = false }
            var authenticated = false
            if policy?.requireAuthentication ?? true {
                authenticated = await authenticate()
                guard authenticated else {
                    alert.show("Authentication was not granted, your user has not been changed.", error: false)
                    return
                }
            }
            requestNotificationAuthorization()
            do {
                let timeout = DaemonClient.longCallTimeout
                let result: AdminRequestResult = try await call(timeout: timeout) { service, reply in
                    service.requestAdmin(seconds: seconds, reason: reason, authenticated: authenticated, reply: reply)
                }
                switch result.outcome {
                case .granted:
                    warned = false
                case .pending:
                    alert.show(result.message ?? "Waiting for an administrator to approve the request...", error: false)
                case .denied:
                    alert.show(result.message ?? "The request was declined!", error: false)
                case .failed:
                    alert.show(result.message ?? "Elevation failed.")
                }
                await refreshStatus()
            } catch {
                alert.show("The background service did not answer: \(error)")
            }
        }
    }

    func demoteNow() {
        guard !busy else {
            return
        }
        busy = true
        Task {
            defer { busy = false }
            do {
                let result: SimpleResult = try await call(timeout: DaemonClient.longCallTimeout) { service, reply in
                    service.revokeAdmin(reply: reply)
                }
                if !result.ok {
                    alert.show(result.message ?? "Admin access could not be removed.")
                }
                await refreshStatus()
            } catch {
                alert.show("The background service did not answer: \(error)")
            }
        }
    }

    func checkInNow() {
        Task {
            do {
                let result: SimpleResult = try await call(timeout: DaemonClient.longCallTimeout) { service, reply in
                    service.checkIn(reply: reply)
                }
                alert.show(result.ok ? "Checked in with the server." : (result.message ?? "Check-in failed."),
                           error: !result.ok)
                await refreshStatus()
            } catch {
                alert.show("The background service did not answer: \(error)")
            }
        }
    }

    func loadFacts() {
        facts = nil
        Task {
            do {
                let data = try await rawCall(timeout: DaemonClient.longCallTimeout) { service, reply in
                    service.collectFacts(reply: reply)
                }
                facts = String(decoding: data, as: UTF8.self)
            } catch {
                facts = "The background service did not answer: \(error)"
            }
        }
    }

    // The system authentication sheet, in this process and as this user, so the daemon never sees a password.
    private func authenticate() async -> Bool {
        let context = LAContext()
        var unavailable: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &unavailable) else {
            alert.show("Authentication is not available: \(unavailable?.localizedDescription ?? "unknown reason")")
            return false
        }
        do {
            return try await context.evaluatePolicy(.deviceOwnerAuthentication,
                                                    localizedReason: "grant temporary administrator access")
        } catch {
            logger.info("authentication declined: \(error.localizedDescription, privacy: .public)")
            return false
        }
    }

    // MARK: - Countdown

    private func startCountdown() {
        guard countdown == nil else {
            return
        }
        countdown = Task { [weak self] in
            while !Task.isCancelled {
                guard let self else {
                    return
                }
                self.tick()
                try? await Task.sleep(for: .seconds(1))
            }
        }
    }

    private func stopCountdown() {
        countdown?.cancel()
        countdown = nil
    }

    private func tick() {
        guard let grant else {
            timeRemaining = 0
            stopCountdown()
            return
        }
        timeRemaining = grant.secondsRemaining
        let warnAt = PreferencesState.shared.notificationWarnSeconds
        if timeRemaining > 0 && timeRemaining <= warnAt && !warned {
            warned = true
            postNotification(title: "Micromanage",
                             body: "Administrator access ends in \(minutesText(timeRemaining)).")
        }
        if timeRemaining <= 0 {
            stopCountdown()
            Task { await refreshStatus() }
        }
    }

    // MARK: - XPC

    private func connect() -> NSXPCConnection {
        if let connection {
            return connection
        }
        let fresh = NSXPCConnection(machServiceName: MicromanageIdentity.machServiceName, options: .privileged)
        fresh.remoteObjectInterface = NSXPCInterface(with: MicromanageDaemonProtocol.self)
        fresh.setCodeSigningRequirement(MicromanageIdentity.daemonRequirement)
        fresh.invalidationHandler = { [weak self] in
            Task { @MainActor in
                self?.connection = nil
            }
        }
        fresh.interruptionHandler = { [weak self] in
            Task { @MainActor in
                self?.connection = nil
            }
        }
        fresh.resume()
        connection = fresh
        return fresh
    }

    private func call<T: Decodable & Sendable>(
        timeout: Duration,
        _ invoke: @escaping @Sendable (MicromanageDaemonProtocol, @escaping @Sendable (Data) -> Void) -> Void
    ) async throws -> T {
        let data = try await rawCall(timeout: timeout, invoke)
        return try JSONCoding.decode(T.self, from: data)
    }

    private func rawCall(
        timeout: Duration,
        _ invoke: @escaping @Sendable (MicromanageDaemonProtocol, @escaping @Sendable (Data) -> Void) -> Void
    ) async throws -> Data {
        let connection = connect()
        return try await withCheckedThrowingContinuation { continuation in
            let once = ResumeOnce<Data>(continuation)
            let proxy = connection.remoteObjectProxyWithErrorHandler { error in
                once.resume(.failure(error))
            }
            guard let service = proxy as? MicromanageDaemonProtocol else {
                once.resume(.failure(DaemonClientError.noProxy))
                return
            }
            Task.detached {
                try? await Task.sleep(for: timeout)
                once.resume(.failure(DaemonClientError.timeout))
            }
            invoke(service) { data in
                once.resume(.success(data))
            }
        }
    }
}
