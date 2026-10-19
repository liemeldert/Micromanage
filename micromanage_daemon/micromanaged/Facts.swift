//
//  Facts.swift
//  micromanaged
//
//  Created by Liem Eldert on 2026/10/05.
//

// Collects and controls system data to provide to the management server

import CryptoKit
import Darwin
import Foundation
import IOKit
import SystemConfiguration

nonisolated enum FactsCollector {
    static let schemaVersion = 1
    static let maxApps = 500
    static let maxUsers = 50

    static func collect() -> [String: Any] {
        var facts: [String: Any] = [
            "schema": schemaVersion,
            "collected_at": ISO8601DateFormatter().string(from: Date()),
        ]
        facts["system"] = system()
        facts["security"] = security()
        facts["mdm"] = mdm()
        facts["users"] = users()
        facts["network"] = network()
        facts["software"] = software()
        facts["agent"] = agent()
        return facts
    }

    nonisolated struct Report: Sendable {
        var value: JSONValue?
        var digest: String
    }

    // The report as the heartbeat carries it, built off the calling actor.
    static func report() -> Report {
        let facts = collect()
        return Report(value: JSONValue(any: facts), digest: digest(facts))
    }

    static func json(_ facts: [String: Any]) -> Data {
        (try? JSONSerialization.data(withJSONObject: facts, options: [.sortedKeys])) ?? Data("{}".utf8)
    }

    static func prettyJSON(_ facts: [String: Any]) -> Data {
        (try? JSONSerialization.data(withJSONObject: facts, options: [.sortedKeys, .prettyPrinted])) ?? Data("{}".utf8)
    }

    // Digest of the report without the timestamp, so an unchanged report is not sent again.
    static func digest(_ facts: [String: Any]) -> String {
        var stable = facts
        stable["collected_at"] = nil
        if var agent = stable["agent"] as? [String: Any] {
            agent["uptime_seconds"] = nil
            stable["agent"] = agent
        }
        if var system = stable["system"] as? [String: Any] {
            system["uptime_seconds"] = nil
            stable["system"] = system
        }
        return SHA256.hash(data: json(stable)).map { String(format: "%02x", $0) }.joined()
    }

    // MARK: Data sections

    static func system() -> [String: Any] {
        var out: [String: Any] = [:]
        out["serial_number"] = platformProperty(kIOPlatformSerialNumberKey)
        out["hardware_uuid"] = platformProperty(kIOPlatformUUIDKey)
        out["model"] = sysctlString("hw.model")
        out["architecture"] = unameMachine()
        let version = ProcessInfo.processInfo.operatingSystemVersion
        out["os_version"] = "\(version.majorVersion).\(version.minorVersion).\(version.patchVersion)"
        out["os_build"] = run("/usr/bin/sw_vers", ["-buildVersion"])
        out["uptime_seconds"] = Int(ProcessInfo.processInfo.systemUptime)
        out["computer_name"] = run("/usr/sbin/scutil", ["--get", "ComputerName"])
        out["host_name"] = run("/usr/sbin/scutil", ["--get", "HostName"])
        out["local_host_name"] = run("/usr/sbin/scutil", ["--get", "LocalHostName"])
        return out.compactMapValues { $0 }
    }

    static func security() -> [String: Any] {
        var out: [String: Any] = [:]
        if let text = run("/usr/bin/fdesetup", ["status"]) {
            out["filevault_enabled"] = text.contains("FileVault is On")
        }
        if let text = run("/usr/bin/csrutil", ["status"]) {
            out["sip_enabled"] = text.lowercased().contains("enabled")
        }
        if let text = run("/usr/libexec/ApplicationFirewall/socketfilterfw", ["--getglobalstate"]) {
            out["firewall_enabled"] = text.contains("enabled")
        }
        if let text = run("/usr/libexec/ApplicationFirewall/socketfilterfw", ["--getstealthmode"]) {
            out["firewall_stealth_mode"] = text.contains("enabled")
        }
        if let text = run("/usr/sbin/spctl", ["--status"]) {
            out["gatekeeper_enabled"] = text.contains("assessments enabled")
        }
        let xprotect = "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist"
        if let plist = NSDictionary(contentsOfFile: xprotect),
           let version = plist["CFBundleShortVersionString"] as? String {
            out["xprotect_version"] = version
        }
        return out
    }

    static func mdm() -> [String: Any] {
        var out: [String: Any] = [:]
        if let text = run("/usr/bin/profiles", ["status", "-type", "enrollment"]) {
            out["dep_enrolled"] = text.contains("Enrolled via DEP: Yes")
            out["mdm_enrolled"] = text.contains("MDM enrollment: Yes")
            out["user_approved"] = text.contains("User Approved")
            if let line = text.split(separator: "\n").first(where: { $0.hasPrefix("MDM server:") }) {
                out["mdm_server"] = line.dropFirst("MDM server:".count).trimmingCharacters(in: .whitespaces)
            }
        }
        if let text = run("/usr/bin/profiles", ["status", "-type", "bootstraptoken"]) {
            out["bootstrap_token_supported"] = text.contains("supported on server: YES")
            out["bootstrap_token_escrowed"] = text.contains("escrowed to server: YES")
        }
        return out
    }

    static func users() -> [String: Any] {
        var out: [String: Any] = [:]
        var uid: uid_t = 0
        var gid: gid_t = 0
        if let console = SCDynamicStoreCopyConsoleUser(nil, &uid, &gid) as String?, console != "loginwindow" {
            out["console_user"] = console
            out["console_uid"] = Int(uid)
        }
        var accounts: [[String: Any]] = []
        if let listing = run("/usr/bin/dscl", [".", "-list", "/Users", "UniqueID"]) {
            for line in listing.split(separator: "\n") {
                let parts = line.split(separator: " ", omittingEmptySubsequences: true)
                guard parts.count == 2, let userID = Int(parts[1]), userID >= 500 else {
                    continue
                }
                let name = String(parts[0])
                guard !name.hasPrefix("_") else {
                    continue
                }
                var account: [String: Any] = ["name": name, "uid": userID]
                account["admin"] = AdminGrants.isAdmin(name)
                if let token = runEither("/usr/sbin/sysadminctl", ["-secureTokenStatus", name]) {
                    account["secure_token"] = token.contains("ENABLED")
                }
                accounts.append(account)
                if accounts.count >= maxUsers {
                    break
                }
            }
        }
        out["accounts"] = accounts
        return out
    }

    // Collect data from Tailscale, if present
    static func network() -> [String: Any] {
        var out: [String: Any] = [:]
        let candidates = ["/usr/local/bin/tailscale", "/Applications/Tailscale.app/Contents/MacOS/Tailscale"]
        if let tailscale = candidates.first(where: { FileManager.default.isExecutableFile(atPath: $0) }),
           let text = run(tailscale, ["status", "--json"], timeout: 10),
           let data = text.data(using: .utf8),
           let status = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
            var ts: [String: Any] = [:]
            ts["version"] = status["Version"]
            ts["backend_state"] = status["BackendState"]
            if let me = status["Self"] as? [String: Any] {
                ts["ips"] = me["TailscaleIPs"]
                ts["host_name"] = me["HostName"]
                ts["dns_name"] = me["DNSName"]
                ts["tags"] = me["Tags"]
                ts["online"] = me["Online"]
            }
            out["tailscale"] = ts.compactMapValues { $0 }
        }
        return out
    }

    static func software() -> [String: Any] {
        var apps: [[String: Any]] = []
        let roots = ["/Applications", "/Applications/Utilities"]
        for root in roots {
            guard let names = try? FileManager.default.contentsOfDirectory(atPath: root) else {
                continue
            }
            for name in names.sorted() where name.hasSuffix(".app") {
                let path = root + "/" + name
                guard let plist = NSDictionary(contentsOfFile: path + "/Contents/Info.plist") else {
                    continue
                }
                var app: [String: Any] = ["path": path, "name": String(name.dropLast(4))]
                app["bundle_id"] = plist["CFBundleIdentifier"]
                app["version"] = plist["CFBundleShortVersionString"]
                app["build"] = plist["CFBundleVersion"]
                apps.append(app.compactMapValues { $0 })
                if apps.count >= maxApps {
                    return ["apps": apps, "count": apps.count, "truncated": true]
                }
            }
        }
        return ["apps": apps, "count": apps.count, "truncated": false]
    }

    static func agent() -> [String: Any] {
        [
            "version": DaemonInfo.version,
            "started_at": ISO8601DateFormatter().string(from: DaemonInfo.startedAt),
            "uptime_seconds": Int(Date().timeIntervalSince(DaemonInfo.startedAt)),
            "running_as_root": DaemonInfo.isRoot,
        ]
    }

    // MARK: helper functions

    private static func run(_ executable: String, _ arguments: [String], timeout: TimeInterval = 15) -> String? {
        guard let result = try? Shell.run(executable, arguments, timeout: timeout), result.ok else {
            return nil
        }
        let text = result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
        return text.isEmpty ? nil : text
    }

    private static func runEither(_ executable: String, _ arguments: [String]) -> String? {
        guard let result = try? Shell.run(executable, arguments, timeout: 15) else {
            return nil
        }
        let text = result.output
        return text.isEmpty ? nil : text
    }

    private static func platformProperty(_ key: String) -> String? {
        let service = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOPlatformExpertDevice"))
        guard service != 0 else {
            return nil
        }
        defer { IOObjectRelease(service) }
        guard let value = IORegistryEntryCreateCFProperty(service, key as CFString, kCFAllocatorDefault, 0) else {
            return nil
        }
        return (value.takeRetainedValue() as? String)?.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private static func sysctlString(_ name: String) -> String? {
        var size = 0
        guard sysctlbyname(name, nil, &size, nil, 0) == 0, size > 0 else {
            return nil
        }
        var buffer = [CChar](repeating: 0, count: size)
        guard sysctlbyname(name, &buffer, &size, nil, 0) == 0 else {
            return nil
        }
        return String(cString: buffer)
    }

    private static func unameMachine() -> String? {
        var info = utsname()
        guard uname(&info) == 0 else {
            return nil
        }
        return withUnsafePointer(to: &info.machine) { pointer in
            pointer.withMemoryRebound(to: CChar.self, capacity: Int(_SYS_NAMELEN)) { String(cString: $0) }
        }
    }
}
