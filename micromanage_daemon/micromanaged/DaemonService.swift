//
//  DaemonService.swift
//  micromanaged
//
//  Created by Liem Eldert on 2026/10/05.
//

import Foundation
import os

// Main XPC service, which is pinned to the identity of the menubar-extra application
final class DaemonService: NSObject, NSXPCListenerDelegate {
    private let listener: NSXPCListener
    private let coordinator: Coordinator
    private let grants: AdminGrants

    init(coordinator: Coordinator, grants: AdminGrants) {
        self.listener = NSXPCListener(machServiceName: MicromanageIdentity.machServiceName)
        self.coordinator = coordinator
        self.grants = grants
        super.init()
        listener.delegate = self
    }

    func start() {
        listener.resume()
        logger.info("listening on \(MicromanageIdentity.machServiceName, privacy: .public)")
    }

    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection newConnection: NSXPCConnection) -> Bool {
        newConnection.setCodeSigningRequirement(MicromanageIdentity.appRequirement)
        let uid = newConnection.effectiveUserIdentifier
        newConnection.exportedInterface = NSXPCInterface(with: MicromanageDaemonProtocol.self)
        newConnection.exportedObject = ConnectionHandler(uid: uid, coordinator: coordinator)
        newConnection.invalidationHandler = {
            logger.debug("connection from uid \(uid) closed")
        }
        newConnection.resume()
        logger.info("accepted a connection from uid \(uid)")
        return true
    }
}

final class ConnectionHandler: NSObject, MicromanageDaemonProtocol, @unchecked Sendable {
    private let uid: uid_t
    private let coordinator: Coordinator

    init(uid: uid_t, coordinator: Coordinator) {
        self.uid = uid
        self.coordinator = coordinator
    }

    private func caller() -> LocalUser? {
        LocalUser.lookup(uid: uid)
    }

    func status(reply: @escaping @Sendable (Data) -> Void) {
        guard let user = caller() else {
            reply(JSONCoding.encode(SimpleResult(ok: false, message: "unknown user \(uid)")))
            return
        }
        Task {
            reply(JSONCoding.encode(await coordinator.status(for: user)))
        }
    }

    func requestAdmin(seconds: Int, reason: String, authenticated: Bool, reply: @escaping @Sendable (Data) -> Void) {
        guard let user = caller() else {
            reply(JSONCoding.encode(AdminRequestResult(outcome: .denied, message: "unknown user \(uid)", grant: nil,
                                                       requestID: nil)))
            return
        }
        Task {
            reply(JSONCoding.encode(await coordinator.requestAdmin(user: user, seconds: seconds, reason: reason,
                                                                   authenticated: authenticated)))
        }
    }

    func revokeAdmin(reply: @escaping @Sendable (Data) -> Void) {
        guard let user = caller() else {
            reply(JSONCoding.encode(SimpleResult(ok: false, message: "unknown user \(uid)")))
            return
        }
        Task {
            reply(JSONCoding.encode(await coordinator.revokeAdmin(user: user)))
        }
    }

    func checkIn(reply: @escaping @Sendable (Data) -> Void) {
        Task {
            reply(JSONCoding.encode(await coordinator.checkInNow()))
        }
    }

    func collectFacts(reply: @escaping @Sendable (Data) -> Void) {
        Task.detached(priority: .utility) {
            reply(FactsCollector.prettyJSON(FactsCollector.collect()))
        }
    }
}
