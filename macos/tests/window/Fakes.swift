import Foundation

final class ShellLog: @unchecked Sendable {
    private let lock = NSLock()
    private var entries: [String] = []
    func info(_ message: String) { record(message) }
    func error(_ message: String) { record(message) }
    private func record(_ message: String) {
        lock.lock(); defer { lock.unlock() }
        entries.append(message)
    }
}

/// No Keychain, database, process launch, or file logging occurs in this fake.
final class Supervisor: @unchecked Sendable {
    let log = ShellLog()
    let support: URL
    let logDir: URL
    var onProgress: (@Sendable (String, String) -> Void)?
    var onUnexpectedExit: (@Sendable (String) -> Void)?
    let releaseStart: DispatchSemaphore
    private let lock = NSLock()
    private let testPort: Int
    private var stopping = false
    private var stops = 0
    private var entered = false
    private var returned = false

    init(port: Int, directory: URL, delayedStart: Bool = false) {
        testPort = port
        support = directory
        logDir = directory.appendingPathComponent("logs")
        releaseStart = DispatchSemaphore(value: delayedStart ? 0 : 1)
    }
    var isStopping: Bool { locked { stopping } }
    var stopCount: Int { locked { stops } }
    var startEntered: Bool { locked { entered } }
    var startReturned: Bool { locked { returned } }
    private func locked<T>(_ operation: () -> T) -> T {
        lock.lock(); defer { lock.unlock() }; return operation()
    }
    func start() throws -> Int {
        locked { entered = true }
        releaseStart.wait()
        locked { returned = true }
        return testPort
    }
    func stop() { locked { stops += 1; stopping = true } }
    func claimToken() -> String? { nil }
}
