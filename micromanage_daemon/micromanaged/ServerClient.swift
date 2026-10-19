//
//  ServerClient.swift
//  micromanaged
//
//  Created by Liem Eldert on 2026/10/05.
//

import Foundation

nonisolated struct EnrollRequest: Codable, Sendable {
    var code: String
    var serialNumber: String?
    var hardwareUuid: String?
    var hostname: String?
    var agentVersion: String
}

nonisolated struct EnrollResponse: Codable, Sendable {
    var token: String
    var deviceId: String
    var tenantId: String
    var heartbeatMinutes: Int?
}

nonisolated struct HeartbeatRequest: Codable, Sendable {
    var agentVersion: String
    var facts: JSONValue?
    var factsDigest: String?
    var events: [AgentEvent]
    var pendingRequestIds: [String]
    var grants: [AdminGrantInfo]
}

nonisolated struct AgentTask: Codable, Sendable {
    var id: String
    var type: String
    var params: JSONValue?
}

nonisolated struct JITDecision: Codable, Sendable {
    var requestId: String
    var decision: String
    var minutes: Int?
    var decidedBy: String?
}

nonisolated struct ServerPolicy: Codable, Sendable {
    var admin: ServerAdminPolicy?
}

nonisolated struct HeartbeatResponse: Codable, Sendable {
    var tasks: [AgentTask]?
    var policy: ServerPolicy?
    var heartbeatMinutes: Int?
    var rotateToken: String?
    var jitDecisions: [JITDecision]?
    var factsWanted: Bool?
}

nonisolated struct TaskResult: Codable, Sendable {
    var status: String
    var detail: [String: JSONValue]

    static func completed(_ detail: [String: JSONValue] = [:]) -> TaskResult {
        TaskResult(status: "completed", detail: detail)
    }

    static func failed(_ message: String, _ detail: [String: JSONValue] = [:]) -> TaskResult {
        var merged = detail
        merged["error"] = .string(message)
        return TaskResult(status: "failed", detail: merged)
    }
}

nonisolated struct JITRequest: Codable, Sendable {
    var username: String
    var minutes: Int
    var reason: String?
}

nonisolated struct JITResponse: Codable, Sendable {
    var id: String
    var decision: String
    var minutes: Int?
}

nonisolated enum ServerError: Error, CustomStringConvertible {
    case unauthorized
    case http(Int, String)
    case transport(String)
    case decoding(String)

    var description: String {
        switch self {
        case .unauthorized:
            return "the server no longer accepts this device's credential"
        case .http(let status, let body):
            return "the server answered HTTP \(status)" + (body.isEmpty ? "" : ": \(body)")
        case .transport(let detail):
            return "the server could not be reached: \(detail)"
        case .decoding(let detail):
            return "the server's answer could not be read: \(detail)"
        }
    }
}

// The one HTTP client. Bearer credential, JSON both ways, system trust store, no cookies.
actor ServerClient {
    static let maxErrorBody = 300

    let session: URLSession

    init() {
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 30
        config.timeoutIntervalForResource = 120
        config.httpCookieStorage = nil
        config.httpShouldSetCookies = false
        session = URLSession(configuration: config)
    }

    func enroll(serverURL: URL, request: EnrollRequest) async throws -> EnrollResponse {
        try await send(.post, serverURL, "api/v1/agent/enroll", body: request, token: nil)
    }

    func heartbeat(credential: Credential, request: HeartbeatRequest) async throws -> HeartbeatResponse {
        try await send(.post, credential, "api/v1/agent/heartbeat", body: request)
    }

    func postResult(credential: Credential, taskID: String, result: TaskResult) async throws {
        let _: EmptyResponse = try await send(.post, credential, "api/v1/agent/tasks/\(taskID)/result", body: result)
    }

    func requestJIT(credential: Credential, request: JITRequest) async throws -> JITResponse {
        try await send(.post, credential, "api/v1/agent/jit/requests", body: request)
    }

    // MARK: - Transport

    nonisolated enum Method: String {
        case get = "GET"
        case post = "POST"
    }

    private struct EmptyResponse: Decodable {}

    private func send<T: Decodable, B: Encodable>(_ method: Method, _ credential: Credential, _ path: String,
                                                  body: B?) async throws -> T {
        guard let base = URL(string: credential.serverURL) else {
            throw ServerError.transport("the stored server address is not a URL")
        }
        return try await send(method, base, path, body: body, token: credential.token)
    }

    private func send<T: Decodable, B: Encodable>(_ method: Method, _ base: URL, _ path: String, body: B?,
                                                  token: String?) async throws -> T {
        var request = URLRequest(url: base.appending(path: path))
        request.httpMethod = method.rawValue
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("micromanaged/\(DaemonInfo.version)", forHTTPHeaderField: "User-Agent")
        if let token {
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }
        if let body {
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            request.httpBody = try JSONCoding.encoder().encode(body)
        }
        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await session.data(for: request)
        } catch {
            throw ServerError.transport(error.localizedDescription)
        }
        guard let http = response as? HTTPURLResponse else {
            throw ServerError.transport("no HTTP response")
        }
        if http.statusCode == 401 {
            throw ServerError.unauthorized
        }
        guard (200..<300).contains(http.statusCode) else {
            let text = String(decoding: data.prefix(ServerClient.maxErrorBody), as: UTF8.self)
            throw ServerError.http(http.statusCode, text)
        }
        do {
            return try JSONCoding.decode(T.self, from: data.isEmpty ? Data("{}".utf8) : data)
        } catch {
            throw ServerError.decoding(error.localizedDescription)
        }
    }
}
