import Foundation
import Security

/// A failure the shell can only report: its description is the sentence the window and the
/// log show, written to say what failed and what to check (docs/diagnosability.md).
struct ShellFailure: Error, CustomStringConvertible {
    let description: String
    init(_ description: String) { self.description = description }
    static let stopping = ShellFailure("LoonInspect is quitting.")
}

/// logs/shell.log, one timestamped line per event, mirrored to stderr for --headless runs.
final class ShellLog: @unchecked Sendable {
    private let url: URL
    private let queue = DispatchQueue(label: "io.loonsec.looninspect.spike.log")
    private let clock: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter
    }()

    init(url: URL) { self.url = url }

    func info(_ message: String) { write("INFO", message) }
    func error(_ message: String) { write("ERROR", message) }

    private func write(_ level: String, _ message: String) {
        queue.sync {
            let line = Data("\(clock.string(from: Date())) \(level) \(message)\n".utf8)
            FileHandle.standardError.write(line)
            if let handle = try? appendHandle(url) {
                handle.write(line)
                try? handle.close()
            }
        }
    }
}

/// Opens `url` for appending, creating it 0600. Close-on-exec, so no child inherits it by accident.
func appendHandle(_ url: URL) throws -> FileHandle {
    let fd = open(url.path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0o600)
    guard fd >= 0 else {
        throw ShellFailure("Could not open \(url.path) for writing: \(String(cString: strerror(errno))).")
    }
    return FileHandle(fileDescriptor: fd, closeOnDealloc: true)
}

/// Writes a file only this user can read, failing rather than replacing one that exists.
func writePrivate(_ url: URL, _ contents: String) throws {
    let fd = open(url.path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0o600)
    guard fd >= 0 else { throw ShellFailure("Could not create \(url.path): \(String(cString: strerror(errno))).") }
    let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
    handle.write(Data(contents.utf8))
    try handle.close()
}

struct ToolResult {
    let status: Int32
    let stdout: String
    let stderr: String
}

/// Runs a short-lived tool to completion: initdb, single-user postgres, pg_ctl, security, ps.
func runTool(_ path: String, _ arguments: [String], stdin: String? = nil, environment: [String: String]? = nil) throws -> ToolResult {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: path)
    process.arguments = arguments
    if let environment { process.environment = environment }
    let output = Pipe(), errors = Pipe(), input = Pipe()
    process.standardOutput = output
    process.standardError = errors
    process.standardInput = stdin == nil ? FileHandle.nullDevice : input
    try process.run()
    if let stdin {
        input.fileHandleForWriting.write(Data(stdin.utf8))
        try? input.fileHandleForWriting.close()
    }
    var out = Data(), err = Data()
    let group = DispatchGroup()
    group.enter()
    DispatchQueue.global().async { out = output.fileHandleForReading.readDataToEndOfFile(); group.leave() }
    group.enter()
    DispatchQueue.global().async { err = errors.fileHandleForReading.readDataToEndOfFile(); group.leave() }
    group.wait()
    process.waitUntilExit()
    return ToolResult(status: process.terminationStatus,
                      stdout: String(decoding: out, as: UTF8.self),
                      stderr: String(decoding: err, as: UTF8.self))
}

/// Random bytes from the system's CSPRNG.
func randomBytes(_ count: Int) -> Data {
    var bytes = [UInt8](repeating: 0, count: count)
    precondition(SecRandomCopyBytes(kSecRandomDefault, count, &bytes) == errSecSuccess, "SecRandomCopyBytes failed")
    return Data(bytes)
}

/// The secrets in the login keychain: generic passwords under one service, read and written
/// through /usr/bin/security rather than SecItem.
///
/// The indirection is deliberate for an ad-hoc signed spike. A legacy keychain item trusts the
/// code signature that created it, and an ad-hoc signature is a hash of the binary, so every
/// rebuild of the shell would meet an "allow access" prompt — one a --headless run cannot answer.
/// Items `security` creates trust `security`, which Apple signs and which does not change. A
/// value is written on its stdin (`security -i`), never in an argument `ps` could show. With a
/// Developer ID signature this becomes plain SecItem calls (docs/spike-macos-app.md).
enum Keychain {
    static let service = "LoonInspect-Spike"
    private static let tool = "/usr/bin/security"
    private static let notFound: Int32 = 44

    static func read(_ account: String) throws -> String? {
        let result = try runTool(tool, ["find-generic-password", "-s", service, "-a", account, "-w"])
        if result.status == notFound { return nil }
        guard result.status == 0 else {
            throw ShellFailure("Reading \(account) from the login keychain failed (security exited \(result.status)): "
                + "\(result.stderr.trimmingCharacters(in: .whitespacesAndNewlines)). Check that the login keychain is unlocked.")
        }
        let value = result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
        return value.isEmpty ? nil : value
    }

    static func add(_ account: String, _ value: String) throws {
        guard value.allSatisfy({ $0.isLetter || $0.isNumber || "-_=".contains($0) }) else {
            throw ShellFailure("Refusing to store a keychain value with characters `security -i` would parse.")
        }
        let result = try runTool(tool, ["-i"], stdin: "add-generic-password -s \(service) -a \(account) -w \(value)\n")
        guard result.status == 0 else {
            throw ShellFailure("Saving \(account) to the login keychain failed (security exited \(result.status)): "
                + "\(result.stderr.trimmingCharacters(in: .whitespacesAndNewlines)). Check that the login keychain is unlocked.")
        }
    }
}
