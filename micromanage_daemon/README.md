# Micromanage for Mac

The Mac client for Micromanage. It is one app bundle with two programs inside:

* `micromanaged`, a LaunchDaemon that runs as root. It owns everything that needs privilege: time-boxed admin group
  membership, package installs, hostname changes, facts collection and the conversation with the server.
* `Micromanage`, a menu bar app that runs as the signed-in user. It shows the state, asks for admin access, and
  registers the daemon with launchd.

Without a server address the daemon runs in local mode: self-service admin elevation under the local policy, and nothing
leaves the Mac. With a server address pushed through a configuration profile it enrolls, sends facts and events on a
cadence, and runs the tasks the server hands back. The server side of that contract is described at the end of this
file and is not implemented in the controller yet.

## Layout

```
micromanaged.xcodeproj/        two targets, micromanage-extra depends on micromanaged
micromanaged/                  the daemon
  main.swift                   entry point
  Daemon.swift                 wiring, logger, process facts
  DaemonService.swift          the XPC listener
  Coordinator.swift            heartbeat loop, enrollment, approval flow, answers for the XPC service
  AdminGrants.swift            admin group membership with expiry
  TaskRunner.swift             the server task types
  Facts.swift                  what the Mac reports
  Configuration.swift          managed preferences
  AgentState.swift             credential, grants and state on disk
  ServerClient.swift           the HTTP client and the request and response bodies
  Shell.swift, JSONValue.swift helpers
  Info.plist, micromanaged.entitlements
micromanage-extra/             the menu bar app
  micromanage_extraApp.swift   scenes and the app delegate
  DaemonClient.swift           registration, polling, authentication, the XPC connection
  ContentView.swift            the menu bar window
  SettingsView.swift           preferences and the settings tabs
  OnboardView.swift            the Login Items and first launch windows
  MenuBarIconState.swift, Utils.swift
micromanage-shared/            compiled into both targets: identities, the XPC protocol, the DTOs
Support/                       the launchd plist embedded in the app bundle
```

The built app looks like this:

```
Micromanage.app/Contents/MacOS/micromanage-extra
Micromanage.app/Contents/MacOS/micromanaged
Micromanage.app/Contents/Library/LaunchDaemons/app.micromanage.micromanaged.plist
```

## Build

Xcode 26.6 or newer. The shared `micromanage-extra` scheme builds both targets and embeds the daemon and its plist.
From the command line:

```sh
xcodebuild -project micromanaged.xcodeproj -scheme micromanage-extra -configuration Debug build
```

If `xcode-select` points at the Command Line Tools, set `DEVELOPER_DIR` to the Xcode you want, for example
`DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer`. Keep the project format at Xcode 16 (object version 77)
when Xcode offers to upgrade it, since the CodeQL workflow builds the app with the newest Xcode on GitHub's runners.

Build settings worth knowing about:

* Deployment target macOS 14. Hardened runtime on. No app sandbox, the app has to talk to a privileged mach service.
* Member import visibility is on, so every module whose members a file uses has to be imported in that file.
* The app target defaults to main actor isolation. Shared types are declared `nonisolated` so the daemon can use them.

## Signing and distribution

Each side of the XPC connection checks the other's code signature: the bundle identifier and the team in the signing
certificate. The team is `MicromanageIdentity.teamIdentifier` in `micromanage-shared/DaemonProtocol.swift`. A build
signed by another team has to change it there, or the app and the daemon will refuse each other.

For release, sign both programs with a Developer ID Application certificate, notarize the app, and install it under
`/Applications`. The app warns when it is started from anywhere else. A signed installer package needs a Developer ID
Installer certificate on top of that.

## The background service

The app registers the daemon with `SMAppService` using the embedded plist. The plist declares the mach service
`app.micromanage.micromanaged.xpc`, keeps the daemon alive, and names the app as the owner so System Settings shows it
under the app's name.

Allowing a daemon under Login Items is an administrator action. On a Mac with a standard user the registration stays in
the waiting state until an administrator approves it, so a managed fleet should pre-approve it with a managed login
items payload. This one approves everything signed by the team, which covers the daemon and the app's own login item:

```xml
<key>PayloadType</key>
<string>com.apple.servicemanagement</string>
<key>Rules</key>
<array>
    <dict>
        <key>RuleType</key>
        <string>TeamIdentifier</string>
        <key>RuleValue</key>
        <string>HPJXNWSN57</string>
        <key>Comment</key>
        <string>Micromanage background service and menu bar app</string>
    </dict>
</array>
```

A `Label` rule with `app.micromanage.micromanaged` approves only the daemon.

Without the payload the app opens Login Items, shows a window with the steps, and checks for about five minutes whether
the service was allowed. Advanced settings has Register, Unregister and Refresh for the service.

## Configuration

### Daemon

Domain `app.micromanage.micromanaged`. The server keys are honored only when a configuration profile forced them, so a
local administrator cannot point the daemon at another server with `defaults write`. The other keys are read from the
profile or from `/Library/Preferences/app.micromanage.micromanaged.plist` when root wrote them.

| Key                     | Type       | Default   | Meaning                                                       |
|-------------------------|------------|-----------|---------------------------------------------------------------|
| `ServerURL`             | string     | none      | Base URL of the server. Profile only. Unset means local mode. |
| `TenantID`              | string     | none      | Shown until enrollment supplies the real one. Profile only.   |
| `EnrollmentCode`        | string     | none      | Single-use code for enrollment. Profile only.                 |
| `HeartbeatMinutes`      | integer    | 15        | Check-in cadence, 1 to 1440. The server may send another.     |
| `AllowedTeamIDs`        | [string]   | empty     | Package signers accepted by `install_package`.                |
| `AllowUnsignedPackages` | bool       | false     | Accept unsigned packages when no team list is set.            |
| `FactsEnabled`          | bool       | true      | Send facts with the heartbeat.                                |
| `AdminPolicy`           | dictionary | see below | The elevation policy.                                         |

`AdminPolicy` keys:

| Key                     | Type     | Default | Meaning                                                    |
|-------------------------|----------|---------|------------------------------------------------------------|
| `Enabled`               | bool     | true    | Off refuses every request.                                 |
| `MaxMinutes`            | integer  | 60      | Longest grant, 1 to 1440. Requests above it are clamped.   |
| `DefaultMinutes`        | integer  | 15      | Length of a server `grant_admin` task without `minutes`.   |
| `RequireApproval`       | bool     | false   | Server mode only: each request waits for an administrator. |
| `RequireAuthentication` | bool     | true    | The user authenticates in the app before each request.     |
| `AllowedUsers`          | [string] | empty   | When set, only these local users may elevate.              |
| `BlockedUsers`          | [string] | empty   | These local users may never elevate.                       |

Package signature rule: with `AllowedTeamIDs` set, the package has to be signed by one of those teams. With the list
empty, any signed package passes, and an unsigned one passes only when `AllowUnsignedPackages` is true or the task says
`allow_unsigned`. The sha256 is always required.

The daemon reads the configuration again for every XPC call and every round of its loop, so a policy change applies
at once and a new server address within a minute in local mode.

A Debug build reads the server keys from plain defaults when `AllowLocalConfig` is true in the same domain. Release
builds ignore that key.

### App

Domain `app.micromanage.micromanage-extra`, written as the user, so no `sudo`.

| Key                       | Type    | Default | Meaning                                                 |
|---------------------------|---------|---------|---------------------------------------------------------|
| `DefaultMinutes`          | integer | 15      | The length offered when the menu opens.                 |
| `NotificationWarnSeconds` | integer | 120     | Notification this long before access ends. Zero is off. |
| `ResetDefaultTime`        | bool    | false   | Go back to the default length each time the menu opens. |
| `FirstLaunch`             | bool    | true    | Shows the first launch window once.                     |

## Admin elevation

1. The user picks a length and presses Elevate. With `RequireAuthentication` on, the app shows the system
   authentication sheet in its own process, so the daemon never sees a password.
2. The app calls the daemon over XPC. The daemon accepts the connection only from the app's code identity, and takes
   the requesting user from the connection's effective uid. The app cannot name another user.
3. The daemon checks the policy: a real local account with a uid of 500 or more, not blocked, on the allow list when
   there is one, length clamped to `MaxMinutes`.
4. In local mode, or when approval is not required, it adds the user to the admin group with `dseditgroup` and
   verifies the membership. With `RequireApproval` it files a request with the server and the app shows the waiting
   state until a decision arrives with a heartbeat.
5. The grant is written to disk. A timer and a 30 second sweep take the membership back when it runs out, with
   retries. At start the daemon demotes anyone whose grant expired while it was down, so a restart or a reboot never
   leaves an admin behind. Demote now ends a grant early.

## State and logs

Root keeps state in `/Library/Application Support/Micromanage`, a directory of mode 0700 with files of mode 0600:
`credential.json`, `grants.json`, `state.json` (events, pending requests, last check-in, the server policy) and
`downloads/` for packages. Run as a normal user, for development, the same layout is created under the user's own
`Library/Application Support/Micromanage`.

```sh
log stream --predicate 'subsystem == "app.micromanage.micromanaged"' --level info
log stream --predicate 'subsystem == "app.micromanage.micromanage-extra"' --level info
```

Settings, Advanced, "Show what this Mac reports" prints the facts the daemon would send.

## Server contract

The controller does not implement these endpoints yet. The daemon expects the following. Bodies are JSON with snake_case
keys and ISO 8601 dates. After enrollment every request carries `Authorization: Bearer <token>`. A 401 on the
heartbeat makes the daemon drop its credential and wait for a new `EnrollmentCode`. Any other failure backs off from
two minutes, doubling up to thirty, and shows in the app as the last error.

`POST /api/v1/agent/enroll`, no token. Request `code`, `serial_number`, `hardware_uuid`, `hostname`, `agent_version`.
Response `token`, `device_id`, `tenant_id`, optional `heartbeat_minutes`.

`POST /api/v1/agent/heartbeat`. Request `agent_version`, `facts` (absent when unchanged), `facts_digest`, `events`,
`pending_request_ids`, `grants`. Response, all optional: `tasks`, `policy` with an `admin` dictionary that overrides
`enabled`, `max_minutes`, `default_minutes`, `require_approval` and `require_authentication`, `heartbeat_minutes`,
`rotate_token`, `jit_decisions`, `facts_wanted`. Each task is `id`, `type`, `params`. Each decision is `request_id`,
`decision` (`approved` or anything else), optional `minutes` and `decided_by`.

`POST /api/v1/agent/tasks/{id}/result`. Body `status` (`completed` or `failed`) and `detail`, a dictionary that holds
`error` when the task failed.

`POST /api/v1/agent/jit/requests`. Request `username`, `minutes`, optional `reason`. Response `id`, `decision`
(`approved`, `pending`, or anything else for a refusal), optional `minutes`.

### Tasks

| Type              | Params                           | Effect                                          |
|-------------------|----------------------------------|-------------------------------------------------|
| `install_package` | `url`, `sha256`, signing options | Download, verify, check the signature, install. |
| `remove_app`      | `bundle_id`                      | Delete the matching app under `/Applications`.  |
| `set_hostnames`   | `name`                           | ComputerName, HostName and LocalHostName.       |
| `grant_admin`     | `username`, `minutes`, `reason`  | A grant under the local policy.                 |
| `revoke_admin`    | `username`                       | End the user's grant now.                       |
| `collect_facts`   | none                             | Full facts with the next heartbeat.             |

`install_package` takes an https `url` and the `sha256`. The optional `allowed_team_ids` and `allow_unsigned` add to
the managed `AllowedTeamIDs` and `AllowUnsignedPackages`.

### Facts

Sent when their digest changes, every six hours anyway, when the server answers `facts_wanted`, or after a
`collect_facts` task. Sections: `system` (serial, hardware UUID, model, OS, names), `security` (FileVault, SIP,
firewall, Gatekeeper, XProtect), `mdm` (enrollment and bootstrap token state), `users` (console user and local
accounts with admin and Secure Token flags, capped at 50), `network` (Tailscale when installed), `software` (apps
under `/Applications`, capped at 500) and `agent`.

### Events

Queued on the Mac, at most 200, sent with the heartbeat and dropped once the server has answered. Each has `id`,
`kind`, `at`, `username` and a string `detail` map. Kinds: `admin.granted`, `admin.revoked`, `admin.revoke_failed`,
`admin.requested`, `admin.denied`, `admin.grant_failed`.

## Troubleshooting

* The menu says the background service is not running: check Login Items in System Settings, or Advanced settings,
  Register. The service state there says whether it waits for approval.
* The app shows a warning about the Applications folder: move it there and open it again.
* "The background service is not answering": the daemon log shows why. Unregister and Register from Advanced settings
  restarts it.
* The server dropped the credential: push a new `EnrollmentCode` through the profile. The daemon enrolls again on its
  next round.
* Running from Xcode: the menu bar symbol is a ladybug and Quit does nothing. Registering the service from a Debug
  build points launchd at the build directory, so unregister it from Advanced settings before that build goes away.
