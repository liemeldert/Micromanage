//
//  Configuration.swift
//  micromanaged
//
//  Created by Liem Eldert on 2026/10/05.
//

import CoreFoundation
import Foundation
import os

nonisolated struct AdminPolicy: Sendable {
    var enabled = true
    var maxMinutes = 60
    var defaultMinutes = 15
    var requireApproval = false
    var requireAuthentication = true
    var allowedUsers: [String] = []
    var blockedUsers: [String] = []

    // Why this user may not elevate, or nil when the policy allows it.
    func refusal(for username: String) -> String? {
        if !enabled {
            return "Admin elevation is turned off by policy."
        }
        if blockedUsers.contains(username) {
            return "\(username) is not allowed to elevate."
        }
        if !allowedUsers.isEmpty && !allowedUsers.contains(username) {
            return "\(username) is not on the list of users allowed to elevate."
        }
        return nil
    }

    var info: AdminPolicyInfo {
        AdminPolicyInfo(enabled: enabled, maxMinutes: maxMinutes, defaultMinutes: defaultMinutes,
                        requireApproval: requireApproval, requireAuthentication: requireAuthentication)
    }
}

// The server keys are read only from a configuration profile, so a local administrator cannot redirect the daemon
// with defaults write.
nonisolated struct Configuration: Sendable {
    static let domain = MicromanageIdentity.daemonIdentifier

    var serverURL: URL?
    var tenantID: String?
    var enrollmentCode: String?
    var heartbeatMinutes: Int
    var allowedTeamIDs: [String]
    var allowUnsignedPackages: Bool
    var factsEnabled: Bool
    var adminPolicy: AdminPolicy
    var serverSettingsManaged: Bool

    var serverMode: Bool { serverURL != nil }

    static func load() -> Configuration {
        var config = Configuration(serverURL: nil, tenantID: nil, enrollmentCode: nil, heartbeatMinutes: 15,
                                   allowedTeamIDs: [], allowUnsignedPackages: false, factsEnabled: true,
                                   adminPolicy: AdminPolicy(), serverSettingsManaged: false)

        let managed = isForced("ServerURL")
        config.serverSettingsManaged = managed
        if managed || localServerSettingsAllowed() {
            if let raw = string("ServerURL"), let url = URL(string: raw), ["https", "http"].contains(url.scheme) {
                config.serverURL = url
            }
            config.tenantID = string("TenantID")
            config.enrollmentCode = string("EnrollmentCode")
        } else if string("ServerURL") != nil {
            logger.warning("ServerURL is set but not managed by a profile; ignoring the server settings")
        }
        if let minutes = integer("HeartbeatMinutes") {
            config.heartbeatMinutes = min(max(minutes, 1), 1440)
        }
        config.allowedTeamIDs = stringList("AllowedTeamIDs")
        config.allowUnsignedPackages = bool("AllowUnsignedPackages") ?? false
        config.factsEnabled = bool("FactsEnabled") ?? true

        if let policy = dictionary("AdminPolicy") {
            var admin = AdminPolicy()
            admin.enabled = policy["Enabled"] as? Bool ?? admin.enabled
            admin.maxMinutes = clampMinutes(policy["MaxMinutes"], fallback: admin.maxMinutes)
            admin.defaultMinutes = clampMinutes(policy["DefaultMinutes"], fallback: admin.defaultMinutes)
            admin.requireApproval = policy["RequireApproval"] as? Bool ?? admin.requireApproval
            admin.requireAuthentication = policy["RequireAuthentication"] as? Bool ?? admin.requireAuthentication
            admin.allowedUsers = (policy["AllowedUsers"] as? [String]) ?? []
            admin.blockedUsers = (policy["BlockedUsers"] as? [String]) ?? []
            if admin.defaultMinutes > admin.maxMinutes {
                admin.defaultMinutes = admin.maxMinutes
            }
            config.adminPolicy = admin
        }
        return config
    }

    // Debug builds read the server keys from plain defaults when AllowLocalConfig is true.
    private static func localServerSettingsAllowed() -> Bool {
        #if DEBUG
        return bool("AllowLocalConfig") ?? false
        #else
        return false
        #endif
    }

    private static func clampMinutes(_ value: Any?, fallback: Int) -> Int {
        guard let number = value as? NSNumber else {
            return fallback
        }
        return min(max(number.intValue, 1), 24 * 60)
    }

    private static func value(_ key: String) -> Any? {
        CFPreferencesCopyAppValue(key as CFString, domain as CFString)
    }

    private static func isForced(_ key: String) -> Bool {
        CFPreferencesAppValueIsForced(key as CFString, domain as CFString)
    }

    private static func string(_ key: String) -> String? {
        guard let text = value(key) as? String else {
            return nil
        }
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }

    private static func integer(_ key: String) -> Int? {
        (value(key) as? NSNumber)?.intValue
    }

    private static func bool(_ key: String) -> Bool? {
        (value(key) as? NSNumber)?.boolValue
    }

    private static func stringList(_ key: String) -> [String] {
        (value(key) as? [String]) ?? []
    }

    private static func dictionary(_ key: String) -> [String: Any]? {
        value(key) as? [String: Any]
    }
}
