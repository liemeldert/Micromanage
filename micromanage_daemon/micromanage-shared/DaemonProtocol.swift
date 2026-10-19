//
//  DaemonProtocol.swift
//  micromanage-shared
//
//  Created by Liem Eldert on 2026/10/05.
//

import Foundation

// Bundle identifiers and signing team shared by the daemon and the app.
nonisolated enum MicromanageIdentity {
    static let teamIdentifier = "HPJXNWSN57"
    static let daemonIdentifier = "app.micromanage.micromanaged"
    static let appIdentifier = "app.micromanage.micromanage-extra"
    static let machServiceName = "app.micromanage.micromanaged.xpc"
    static let daemonPlistName = "app.micromanage.micromanaged.plist"
    static let stateDirectory = "/Library/Application Support/Micromanage"

    static var daemonRequirement: String { requirement(for: daemonIdentifier) }
    static var appRequirement: String { requirement(for: appIdentifier) }

    private static func requirement(for identifier: String) -> String {
        "anchor apple generic and identifier \"\(identifier)\" and certificate leaf[subject.OU] = \"\(teamIdentifier)\""
    }
}

@objc nonisolated protocol MicromanageDaemonProtocol {
    func status(reply: @escaping @Sendable (Data) -> Void)
    func requestAdmin(seconds: Int, reason: String, authenticated: Bool, reply: @escaping @Sendable (Data) -> Void)
    func revokeAdmin(reply: @escaping @Sendable (Data) -> Void)
    func checkIn(reply: @escaping @Sendable (Data) -> Void)
    func collectFacts(reply: @escaping @Sendable (Data) -> Void)
}

nonisolated struct AdminGrantInfo: Codable, Sendable {
    var username: String
    var grantedAt: Date
    var expiresAt: Date
    var source: String
    var reason: String?

    var secondsRemaining: Int { max(0, Int(expiresAt.timeIntervalSinceNow.rounded(.up))) }
    var totalSeconds: Int { max(1, Int(expiresAt.timeIntervalSince(grantedAt).rounded())) }
}

nonisolated struct AdminPolicyInfo: Codable, Sendable {
    var enabled: Bool
    var maxMinutes: Int
    var defaultMinutes: Int
    var requireApproval: Bool
    var requireAuthentication: Bool
}

nonisolated struct ServerStatus: Codable, Sendable {
    var configured: Bool
    var enrolled: Bool
    var tenantID: String?
    var serverURL: String?
    var deviceID: String?
    var lastCheckIn: Date?
    var lastError: String?
}

nonisolated struct PendingRequestInfo: Codable, Sendable {
    var requestID: String
    var username: String
    var seconds: Int
    var requestedAt: Date
}

nonisolated struct DaemonStatus: Codable, Sendable {
    var daemonVersion: String
    var username: String
    var isAdmin: Bool
    var grant: AdminGrantInfo?
    var pendingRequest: PendingRequestInfo?
    var policy: AdminPolicyInfo
    var server: ServerStatus
}

nonisolated struct AdminRequestResult: Codable, Sendable {
    enum Outcome: String, Codable, Sendable {
        case granted
        case pending
        case denied
        case failed
    }

    var outcome: Outcome
    var message: String?
    var grant: AdminGrantInfo?
    var requestID: String?
}

nonisolated struct SimpleResult: Codable, Sendable {
    var ok: Bool
    var message: String?
}

nonisolated enum JSONCoding {
    static func encoder() -> JSONEncoder {
        let encoder = JSONEncoder()
        encoder.keyEncodingStrategy = .convertToSnakeCase
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.sortedKeys]
        return encoder
    }

    static func decoder() -> JSONDecoder {
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }

    static func encode<T: Encodable>(_ value: T) -> Data {
        (try? encoder().encode(value)) ?? Data("{}".utf8)
    }

    static func decode<T: Decodable>(_ type: T.Type, from data: Data) throws -> T {
        try decoder().decode(type, from: data)
    }
}
