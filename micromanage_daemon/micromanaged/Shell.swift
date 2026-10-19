//
//  Shell.swift
//  micromanaged
//
//  Created by Liem Eldert on 2026/10/05.
//

import Darwin
import Foundation

nonisolated struct ShellResult: Sendable {
    var status: Int32
    var stdout: String
    var stderr: String

    var ok: Bool { status == 0 }
    var output: String { (stdout + "\n" + stderr).trimmingCharacters(in: .whitespacesAndNewlines) }
}

nonisolated enum ShellError: Error, CustomStringConvertible {
    case launchFailed(String, String)
    case timedOut(String, TimeInterval)

    var description: String {
        switch self {
        case .launchFailed(let executable, let reason):
            return "\(executable) could not be started: \(reason)"
        case .timedOut(let executable, let seconds):
            return "\(executable) did not finish within \(Int(seconds)) seconds"
        }
    }
}

// Reads one pipe to the end on its own thread, so a chatty tool cannot stall on a full pipe buffer.
private final class PipeDrain: @unchecked Sendable {
    private let lock = NSLock()
    private var data = Data()
    private let group = DispatchGroup()

    init(_ pipe: Pipe) {
        group.enter()
        DispatchQueue.global(qos: .utility).async {
            let bytes = pipe.fileHandleForReading.readDataToEndOfFile()
            self.lock.lock()
            self.data = bytes
            self.lock.unlock()
            self.group.leave()
        }
    }

    func text() -> String {
        group.wait()
        lock.lock()
        defer { lock.unlock() }
        return String(decoding: data, as: UTF8.self)
    }
}

// Runs shell commands directly as root.
nonisolated enum Shell {
    static func run(_ executable: String, _ arguments: [String] = [], timeout: TimeInterval = 30,
                    environment: [String: String]? = nil) throws -> ShellResult {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        if let environment {
            process.environment = environment
        }
        let stdout = Pipe()
        let stderr = Pipe()
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = stdout
        process.standardError = stderr

        let finished = DispatchGroup()
        finished.enter()
        process.terminationHandler = { _ in finished.leave() }
        do {
            try process.run()
        } catch {
            finished.leave()
            throw ShellError.launchFailed(executable, error.localizedDescription)
        }
        let outDrain = PipeDrain(stdout)
        let errDrain = PipeDrain(stderr)

        if finished.wait(timeout: .now() + timeout) == .timedOut {
            process.terminate()
            if finished.wait(timeout: .now() + 5) == .timedOut {
                kill(process.processIdentifier, SIGKILL)
                _ = finished.wait(timeout: .now() + 5)
            }
            throw ShellError.timedOut(executable, timeout)
        }
        return ShellResult(status: process.terminationStatus, stdout: outDrain.text(), stderr: errDrain.text())
    }

    static func tail(_ path: String, lines: Int) -> String {
        guard let data = FileManager.default.contents(atPath: path) else {
            return ""
        }
        let text = String(decoding: data.suffix(64 * 1024), as: UTF8.self)
        return text.split(separator: "\n", omittingEmptySubsequences: false).suffix(lines).joined(separator: "\n")
    }
}
