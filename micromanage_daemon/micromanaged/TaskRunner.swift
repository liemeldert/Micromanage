//
//  TaskRunner.swift
//  micromanaged
//
//  Created by Liem Eldert on 2026/10/05.
//

import CryptoKit
import Darwin
import Foundation

nonisolated struct TaskContext: Sendable {
    var config: Configuration
    var policy: AdminPolicy
    var downloadsDirectory: URL
}

// The task types the server may send.
nonisolated enum TaskRunner {
    static let installLog = "/var/log/install.log"

    static func run(_ task: AgentTask, context: TaskContext, grants: AdminGrants,
                    session: URLSession) async -> TaskResult {
        switch task.type {
        case "install_package":
            return await installPackage(task, context: context, session: session)
        case "remove_app":
            return removeApp(task)
        case "set_hostnames":
            return setHostnames(task)
        case "grant_admin":
            return await grantAdmin(task, context: context, grants: grants)
        case "revoke_admin":
            return await revokeAdmin(task, grants: grants)
        case "collect_facts":
            return .completed(["facts_queued": .bool(true)])
        default:
            return .failed("unsupported task type \(task.type)")
        }
    }

    // MARK: Package operations

    static func installPackage(_ task: AgentTask, context: TaskContext, session: URLSession) async -> TaskResult {
        guard DaemonInfo.isRoot else {
            return .failed(AdminError.notRoot.description)
        }
        guard let raw = task.params?["url"]?.stringValue, let url = URL(string: raw), url.scheme == "https" else {
            return .failed("install_package needs an https url")
        }
        guard let expected = task.params?["sha256"]?.stringValue?.lowercased(), expected.count == 64 else {
            return .failed("install_package needs the package sha256")
        }
        let destination = context.downloadsDirectory.appending(path: "\(task.id).pkg")
        defer { try? FileManager.default.removeItem(at: destination) }

        do {
            let (temporary, response) = try await session.download(from: url)
            guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
                try? FileManager.default.removeItem(at: temporary)
                return .failed("the package download answered HTTP \((response as? HTTPURLResponse)?.statusCode ?? 0)")
            }
            try? FileManager.default.removeItem(at: destination)
            try FileManager.default.moveItem(at: temporary, to: destination)
            chmod(destination.path, 0o600)
        } catch {
            return .failed("the package could not be downloaded: \(error.localizedDescription)")
        }

        guard let actual = sha256(of: destination) else {
            return .failed("the downloaded package could not be read")
        }
        guard actual == expected else {
            return .failed("the package sha256 does not match",
                           ["expected": .string(expected), "actual": .string(actual)])
        }

        let signature = packageSignature(destination)
        let taskTeams = task.params?["allowed_team_ids"]?.stringList
        let allowedTeams = context.config.allowedTeamIDs + (taskTeams ?? [])
        let allowUnsigned = context.config.allowUnsignedPackages || (task.params?["allow_unsigned"]?.boolValue ?? false)
        if !allowedTeams.isEmpty {
            guard !signature.teamIDs.isEmpty, signature.teamIDs.contains(where: allowedTeams.contains) else {
                return .failed("the package is not signed by an allowed team",
                               ["signer_team_ids": .array(signature.teamIDs.map(JSONValue.string))])
            }
        } else if !signature.signed && !allowUnsigned {
            return .failed("the package is not signed and unsigned packages are not allowed")
        }

        do {
            let result = try Shell.run("/usr/sbin/installer", ["-pkg", destination.path, "-target", "/"], timeout: 1800)
            if result.ok {
                return .completed(["installer_output": .string(String(result.output.suffix(2000))),
                                   "signer_team_ids": .array(signature.teamIDs.map(JSONValue.string))])
            }
            return .failed("installer exited \(result.status)",
                           ["installer_output": .string(String(result.output.suffix(2000))),
                            "install_log": .string(Shell.tail(installLog, lines: 40))])
        } catch {
            return .failed("installer could not run: \(error)")
        }
    }

    nonisolated struct PackageSignature: Sendable {
        var signed: Bool
        var teamIDs: [String]
    }

    static func packageSignature(_ url: URL) -> PackageSignature {
        guard let result = try? Shell.run("/usr/sbin/pkgutil", ["--check-signature", url.path], timeout: 60) else {
            return PackageSignature(signed: false, teamIDs: [])
        }
        let text = result.output
        let signed = result.ok && text.contains("Status: signed")
        var teams: [String] = []
        if let pattern = try? NSRegularExpression(pattern: "\\(([A-Z0-9]{10})\\)") {
            let range = NSRange(text.startIndex..., in: text)
            for match in pattern.matches(in: text, range: range) {
                if let teamRange = Range(match.range(at: 1), in: text) {
                    teams.append(String(text[teamRange]))
                }
            }
        }
        return PackageSignature(signed: signed, teamIDs: teams)
    }

    static func sha256(of url: URL) -> String? {
        guard let handle = try? FileHandle(forReadingFrom: url) else {
            return nil
        }
        defer { try? handle.close() }
        var hasher = SHA256()
        while let chunk = try? handle.read(upToCount: 1024 * 1024), !chunk.isEmpty {
            hasher.update(data: chunk)
        }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }

    // MARK: App operations
    static func removeApp(_ task: AgentTask) -> TaskResult {
        guard DaemonInfo.isRoot else {
            return .failed(AdminError.notRoot.description)
        }
        guard let bundleID = task.params?["bundle_id"]?.stringValue, !bundleID.isEmpty else {
            return .failed("remove_app needs a bundle_id")
        }
        guard let path = locateApp(bundleID: bundleID) else {
            return .completed(["removed": .bool(false),
                               "note": .string("no app with that bundle id under /Applications")])
        }
        do {
            try FileManager.default.removeItem(atPath: path)
            return .completed(["removed": .bool(true), "path": .string(path)])
        } catch {
            return .failed("could not remove \(path): \(error.localizedDescription)")
        }
    }

    // Searches /Applications and /Applications/Utilities for a bundle whose Info.plist matches.
    static func locateApp(bundleID: String) -> String? {
        for root in ["/Applications", "/Applications/Utilities"] {
            guard let names = try? FileManager.default.contentsOfDirectory(atPath: root) else {
                continue
            }
            for name in names where name.hasSuffix(".app") {
                let path = root + "/" + name
                if let plist = NSDictionary(contentsOfFile: path + "/Contents/Info.plist"),
                   plist["CFBundleIdentifier"] as? String == bundleID {
                    return path
                }
            }
        }
        return nil
    }

    // MARK: Hostname

    static func setHostnames(_ task: AgentTask) -> TaskResult {
        guard DaemonInfo.isRoot else {
            return .failed(AdminError.notRoot.description)
        }
        guard let name = task.params?["name"]?.stringValue?.trimmingCharacters(in: .whitespacesAndNewlines),
              !name.isEmpty, name.count <= 63 else {
            return .failed("set_hostnames needs a name of up to 63 characters")
        }
        let hostName = hostSafe(name)
        let plan = [("ComputerName", name), ("HostName", hostName), ("LocalHostName", hostName)]
        var applied: [String: JSONValue] = [:]
        for (key, value) in plan {
            guard let result = try? Shell.run("/usr/sbin/scutil", ["--set", key, value], timeout: 15), result.ok else {
                return .failed("scutil could not set \(key)", applied)
            }
            applied[key] = .string(value)
        }
        return .completed(applied)
    }

    // allows only valid hostname characters
    static func hostSafe(_ name: String) -> String {
        var out = ""
        for scalar in name.unicodeScalars {
            if CharacterSet.alphanumerics.contains(scalar) && scalar.isASCII {
                out.unicodeScalars.append(scalar)
            } else if scalar == "-" || scalar == " " || scalar == "_" || scalar == "." {
                out.append("-")
            }
        }
        while out.hasPrefix("-") {
            out.removeFirst()
        }
        while out.hasSuffix("-") {
            out.removeLast()
        }
        return out.isEmpty ? "Mac" : String(out.prefix(63))
    }

    // MARK: Admin elevation

    static func grantAdmin(_ task: AgentTask, context: TaskContext, grants: AdminGrants) async -> TaskResult {
        guard let username = task.params?["username"]?.stringValue else {
            return .failed("grant_admin needs a username")
        }
        let minutes = min(max(task.params?["minutes"]?.intValue ?? context.policy.defaultMinutes, 1),
                          context.policy.maxMinutes)
        do {
            let user = try LocalUser.lookup(name: username)
            if let refusal = context.policy.refusal(for: user.name) {
                return .failed(refusal)
            }
            let grant = try await grants.grant(user: user, seconds: minutes * 60,
                                               reason: task.params?["reason"]?.stringValue, source: "server")
            return .completed(["grant_id": .string(grant.id),
                               "expires_at": .string(ISO8601DateFormatter().string(from: grant.expiresAt))])
        } catch {
            return .failed(String(describing: error))
        }
    }

    static func revokeAdmin(_ task: AgentTask, grants: AdminGrants) async -> TaskResult {
        guard let username = task.params?["username"]?.stringValue else {
            return .failed("revoke_admin needs a username")
        }
        do {
            let user = try LocalUser.lookup(name: username)
            let removed = await grants.revoke(username: user.name, reason: "revoked by the server")
            return removed ? .completed() : .failed("\(user.name) is still an admin")
        } catch {
            return .failed(String(describing: error))
        }
    }
}
