import Foundation

/// Starts and stops what LoonInspect.app runs: the embedded Postgres, then the backend.
///
/// The container's two services, as two child processes of the app. Everything lives under
/// ~/Library/Application Support/LoonInspect-Spike: `pgdata` (the database), `run` (the Unix
/// socket, the port file, the instance lock), `logs`, and `data`: the backend runs in the
/// support directory, so its relative `./data/audit` lands there as it lands on the container's volume.
/// The first launch runs initdb and creates the application role the way
/// ops/postgres/initdb/10-app-role.sh does; every launch starts Postgres on a Unix socket only
/// (no TCP port), starts the backend on a free 127.0.0.1 port with the container's settings
/// adapted, and waits for /api/health. Quitting stops the backend, then Postgres, in that order.
final class Supervisor: @unchecked Sendable {
    static let supportName = "LoonInspect-Spike"
    /// Names the socket file (.s.PGSQL.5432) only: Postgres listens on no TCP address.
    static let postgresPort = 5432
    static let database = "looninspect"
    static let superuser = "looninspect"
    static let appRole = "looninspect_app"

    let resources: URL
    let support: URL
    let pgdata: URL
    let runDir: URL
    let logDir: URL
    let log: ShellLog

    /// Called when Postgres or the backend exits while nobody asked it to.
    var onUnexpectedExit: (@Sendable (String) -> Void)?

    private let lock = NSLock()
    private var stopping = false
    private var postgres: Process?
    private var backend: Process?
    private var instanceLock: Int32 = -1
    private(set) var port: Int?
    private var backendLogStart: UInt64 = 0
    private let launched = Date()

    init() {
        resources = Bundle.main.resourceURL!
        support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent(Self.supportName, isDirectory: true)
        pgdata = support.appendingPathComponent("pgdata")
        runDir = support.appendingPathComponent("run")
        logDir = support.appendingPathComponent("logs")
        try? FileManager.default.createDirectory(at: logDir, withIntermediateDirectories: true,
                                                 attributes: [.posixPermissions: 0o700])
        log = ShellLog(url: logDir.appendingPathComponent("shell.log"))
    }

    var isStopping: Bool { lock.lock(); defer { lock.unlock() }; return stopping }

    private func bin(_ name: String) -> String { resources.appendingPathComponent("postgres/bin/\(name)").path }
    private func since(_ start: Date) -> String { String(format: "%.2f s", Date().timeIntervalSince(start)) }

    /// A clean environment for every child: nothing from the launching shell (a stray PGDATA,
    /// PYTHONPATH or DATABASE_URL) reaches Postgres or the backend.
    private var baseEnvironment: [String: String] {
        let inherited = ProcessInfo.processInfo.environment
        var env = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "en_US.UTF-8"]
        for key in ["HOME", "USER", "LOGNAME", "TMPDIR"] { env[key] = inherited[key] }
        return env
    }

    // MARK: - start

    /// Brings Postgres and the backend up and returns the port the UI answers on. Blocks for
    /// as long as that takes, so it runs off the main thread.
    func start() throws -> Int {
        log.info("launch: \(Bundle.main.bundlePath), data in \(support.path)")
        try prepareDirectories()
        try takeInstanceLock()
        let fresh = !FileManager.default.fileExists(atPath: pgdata.appendingPathComponent("PG_VERSION").path)
        let secrets = try loadSecrets(fresh: fresh)
        if fresh {
            let began = Date()
            try initializeDatabase(appPassword: secrets.appPassword, superuserPassword: secrets.superuserPassword)
            log.info("first launch: initdb and the application role took \(since(began))")
        }
        try stopOrphanedPostgres()
        try startPostgres()
        log.info("postgres ready, \(since(launched)) after launch")
        let port = try choosePort()
        try startBackend(port: port, secrets: secrets)
        try waitUntilHealthy(port: port)
        log.info("healthy at http://127.0.0.1:\(port)/ \(since(launched)) after launch (\(fresh ? "first" : "warm") launch)")
        return port
    }

    private func prepareDirectories() throws {
        for dir in [support, runDir, logDir, support.appendingPathComponent("data")] {
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true,
                                                    attributes: [.posixPermissions: 0o700])
        }
        // sockaddr_un.sun_path is 104 bytes on macOS, terminator included.
        let socket = runDir.appendingPathComponent(".s.PGSQL.\(Self.postgresPort)").path
        if socket.utf8.count > 103 {
            throw ShellFailure("The database socket would be \(socket), \(socket.utf8.count) bytes, and macOS allows 103 "
                + "for a Unix socket path. This happens with a long home directory path; the spike has no fallback yet "
                + "(docs/spike-macos-app.md).")
        }
    }

    private func takeInstanceLock() throws {
        let path = runDir.appendingPathComponent("shell.lock").path
        let fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw ShellFailure("Could not open \(path): \(String(cString: strerror(errno))).") }
        guard flock(fd, LOCK_EX | LOCK_NB) == 0 else {
            close(fd)
            throw ShellFailure("Another LoonInspect is already running from \(support.path). Quit that one first.")
        }
        instanceLock = fd
    }

    struct Secrets {
        let encryptionKey: String
        let appPassword: String
        let superuserPassword: String
    }

    /// ENCRYPTION_KEY and the two database passwords, from the login keychain. A first launch
    /// creates whichever is missing; a later one refuses to invent a key for a database written
    /// under another, which would leave every stored credential unreadable (KNOWN_ISSUES.md §5).
    private func loadSecrets(fresh: Bool) throws -> Secrets {
        func get(_ account: String, generate: () -> String) throws -> String {
            if let value = try Keychain.read(account) { return value }
            guard fresh else {
                throw ShellFailure("The database in \(pgdata.path) exists, but \(account) is missing from the login keychain "
                    + "(service \(Keychain.service)). Restore that keychain item, or move the data directory aside to start "
                    + "empty; a new value would not open what the database already holds.")
            }
            let value = generate()
            try Keychain.add(account, value)
            log.info("first launch: generated \(account) and saved it to the login keychain")
            return value
        }
        let hex = { randomBytes(32).map { String(format: "%02x", $0) }.joined() }
        // A Fernet key: 32 random bytes, URL-safe base64, as Fernet.generate_key() makes one.
        let fernet = {
            randomBytes(32).base64EncodedString()
                .replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
        }
        let key = try get("ENCRYPTION_KEY", generate: fernet)
        let app = try get("postgres-\(Self.appRole)", generate: hex)
        // The superuser's password is only needed to create the database; a later launch never asks.
        var superuser = ""
        if fresh { superuser = try get("postgres-\(Self.superuser)", generate: hex) }
        return Secrets(encryptionKey: key, appPassword: app, superuserPassword: superuser)
    }

    /// initdb, then what the image's first boot does before Postgres takes connections: the
    /// docker entrypoint's POSTGRES_DB, and initdb/10-app-role.sh's two statements. zonky's build
    /// ships no psql, so the statements go through single-user mode, which also means nothing can
    /// connect while they run. The directory is built under another name and renamed when
    /// complete, so an interrupted first launch leaves nothing a second launch mistakes for a database.
    private func initializeDatabase(appPassword: String, superuserPassword: String) throws {
        guard appPassword.allSatisfy(\.isHexDigit) else {
            throw ShellFailure("The keychain's postgres-\(Self.appRole) value is not the hex this shell generates; not using it in SQL.")
        }
        let fm = FileManager.default
        let building = support.appendingPathComponent("pgdata.initdb")
        let pwfile = runDir.appendingPathComponent("initdb.pw")
        try? fm.removeItem(at: building)
        try? fm.removeItem(at: pwfile)
        try writePrivate(pwfile, superuserPassword + "\n")
        defer { try? fm.removeItem(at: pwfile) }
        let initdbLog = try appendHandle(logDir.appendingPathComponent("initdb.log"))
        defer { try? initdbLog.close() }

        func step(_ what: String, _ result: ToolResult) throws {
            initdbLog.write(Data("== \(what) (exit \(result.status))\n\(result.stdout)\(result.stderr)\n".utf8))
            guard result.status == 0 else {
                throw ShellFailure("First launch could not create the database: \(what) exited \(result.status). "
                    + "Its output is in \(logDir.path)/initdb.log; nothing was kept, so the next launch starts over.")
            }
        }
        try step("initdb", try runTool(bin("initdb"), [
            "-D", building.path, "-U", Self.superuser, "--pwfile=\(pwfile.path)", "--auth=scram-sha-256",
            "--encoding=UTF8", "--locale=C", "--locale-provider=builtin", "--builtin-locale=C.UTF-8", "--no-instructions",
        ], environment: baseEnvironment))
        // exit_on_error: single-user mode otherwise exits 0 after an error. log_min_error_statement:
        // a failing CREATE ROLE would otherwise be echoed, password and all, into initdb.log.
        let single = ["--single", "-D", building.path, "-c", "exit_on_error=on", "-c", "log_min_error_statement=panic"]
        try step("CREATE DATABASE", try runTool(bin("postgres"), single + ["postgres"],
                                                 stdin: "CREATE DATABASE \(Self.database)\n", environment: baseEnvironment))
        let roleSQL = "CREATE ROLE \(Self.appRole) LOGIN PASSWORD '\(appPassword)' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS\n"
            + "ALTER SCHEMA public OWNER TO \(Self.appRole)\n"
        try step("application role", try runTool(bin("postgres"), single + [Self.database], stdin: roleSQL, environment: baseEnvironment))
        try fm.moveItem(at: building, to: pgdata)
    }

    /// A postmaster.pid whose process is alive and is this data directory's postgres means an
    /// earlier session died without stopping it. We hold the instance lock, so it is nobody's.
    private func stopOrphanedPostgres() throws {
        guard let text = try? String(contentsOf: pgdata.appendingPathComponent("postmaster.pid"), encoding: .utf8),
              let line = text.split(separator: "\n").first, let pid = Int32(line), kill(pid, 0) == 0 else { return }
        let command = try runTool("/bin/ps", ["-p", "\(pid)", "-o", "command="]).stdout
        guard command.contains(pgdata.path) else { return }
        log.info("stopping postgres PID \(pid), left running by an earlier session")
        try stopPostgresCleanly()
    }

    private func postmasterStatus(of pid: Int32) -> String? {
        guard let text = try? String(contentsOf: pgdata.appendingPathComponent("postmaster.pid"), encoding: .utf8) else { return nil }
        let lines = text.components(separatedBy: "\n")
        guard lines.count > 7, Int32(lines[0]) == pid else { return nil }
        return lines[7].trimmingCharacters(in: .whitespaces)
    }

    private func startPostgres() throws {
        let logURL = logDir.appendingPathComponent("postgres.log")
        let handle = try appendHandle(logURL)
        let process = Process()
        process.executableURL = URL(fileURLWithPath: bin("postgres"))
        process.arguments = ["-D", pgdata.path, "-c", "listen_addresses=", "-c", "unix_socket_directories=\(runDir.path)",
                             "-c", "port=\(Self.postgresPort)"]
        process.environment = baseEnvironment
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = handle
        process.standardError = handle
        try launch(process, name: "postgres") { $0.postgres = $1 }
        let deadline = Date().addingTimeInterval(60)
        // pg_ctl -w's own test: the status line of postmaster.pid, for this PID, reads "ready".
        while postmasterStatus(of: process.processIdentifier) != "ready" {
            if isStopping { throw ShellFailure.stopping }
            guard process.isRunning else {
                throw ShellFailure("Postgres exited while starting (status \(process.terminationStatus)). Its log is "
                    + "\(logURL.path); the last lines:\n\(tail(logURL))")
            }
            guard Date() < deadline else {
                throw ShellFailure("Postgres did not report ready within 60 s. Its log is \(logURL.path).")
            }
            usleep(50_000)
        }
    }

    /// The port used last time if it is still free, so the UI's origin (and its per-origin
    /// storage) survives a relaunch; otherwise any free one. Written to run/port either way.
    private func choosePort() throws -> Int {
        let remembered = support.appendingPathComponent("preferred-port")
        var chosen: Int?
        if let text = try? String(contentsOf: remembered, encoding: .utf8), let last = Int(text.trimmingCharacters(in: .whitespacesAndNewlines)),
           (try? bindLoopback(last)) != nil {
            chosen = last
        }
        let port = try chosen ?? bindLoopback(0)
        try "\(port)\n".write(to: remembered, atomically: true, encoding: .utf8)
        try "\(port)\n".write(to: runDir.appendingPathComponent("port"), atomically: true, encoding: .utf8)
        self.port = port
        return port
    }

    /// Binds 127.0.0.1:`port` (0 = any) the way uvicorn will, SO_REUSEADDR included, and
    /// returns the port bound. Released at once; the backend binds it a moment later.
    private func bindLoopback(_ port: Int) throws -> Int {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { throw ShellFailure("socket() failed: \(String(cString: strerror(errno)))") }
        defer { close(fd) }
        var yes: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, socklen_t(MemoryLayout<Int32>.size))
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = in_port_t(UInt16(port).bigEndian)
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        var size = socklen_t(MemoryLayout<sockaddr_in>.size)
        let bound = withUnsafeMutablePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, size) == 0 && getsockname(fd, $0, &size) == 0 }
        }
        guard bound else { throw ShellFailure("No free port on 127.0.0.1: \(String(cString: strerror(errno))).") }
        return Int(UInt16(bigEndian: addr.sin_port))
    }

    /// The image's CMD with the container's environment, adapted for one user's Mac: loopback
    /// only and plain HTTP (TLS_MODE=off), the database over the Unix socket (asyncpg reads the
    /// socket directory from `host=`; the path is literal, because a %-escape would trip
    /// Alembic's ConfigParser), cookies without Secure (the server is reachable only on
    /// 127.0.0.1, and WebKit's handling of Secure cookies over http://127.0.0.1 is not one to
    /// lean on), and no update check (its banner tells an operator to pull an image).
    private func startBackend(port: Int, secrets: Secrets) throws {
        let logURL = logDir.appendingPathComponent("backend.log")
        let handle = try appendHandle(logURL)
        backendLogStart = (try? handle.seekToEnd()) ?? 0
        var env = baseEnvironment
        env["PYTHONPATH"] = resources.appendingPathComponent("backend").path
        env["PYTHONNOUSERSITE"] = "1"
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        env["PYTHONUNBUFFERED"] = "1"
        env["HOST"] = "127.0.0.1"
        env["PORT"] = "\(port)"
        env["TLS_MODE"] = "off"
        env["DATABASE_MODE"] = "bundled"
        env["DATABASE_URL"] = "postgresql+asyncpg://\(Self.appRole):\(secrets.appPassword)@/\(Self.database)?host=\(runDir.path)"
        env["ENCRYPTION_KEY"] = secrets.encryptionKey
        env["SECURE_COOKIES"] = "false"
        env["UPDATE_CHECK"] = "false"
        let process = Process()
        process.executableURL = resources.appendingPathComponent("python/bin/python3")
        process.arguments = [resources.appendingPathComponent("launcher/loon_backend.py").path]
        process.currentDirectoryURL = support
        process.environment = env
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = handle
        process.standardError = handle
        try launch(process, name: "backend") { $0.backend = $1 }
    }

    private func waitUntilHealthy(port: Int) throws {
        let url = URL(string: "http://127.0.0.1:\(port)/api/health")!
        let logURL = logDir.appendingPathComponent("backend.log")
        let deadline = Date().addingTimeInterval(180)
        while httpStatus(url) != 200 {
            if isStopping { throw ShellFailure.stopping }
            lock.lock(); let process = backend; lock.unlock()
            if let process, !process.isRunning {
                throw ShellFailure("The backend exited while starting (status \(process.terminationStatus)). Its log is "
                    + "\(logURL.path); the last lines:\n\(tail(logURL))")
            }
            guard Date() < deadline else {
                throw ShellFailure("The backend did not answer /api/health with 200 within 180 s. Its log is \(logURL.path).")
            }
            usleep(200_000)
        }
    }

    private let probe = URLSession(configuration: .ephemeral)

    private func httpStatus(_ url: URL) -> Int? {
        let request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 3)
        let done = DispatchSemaphore(value: 0)
        var status: Int?
        probe.dataTask(with: request) { _, response, _ in
            status = (response as? HTTPURLResponse)?.statusCode
            done.signal()
        }.resume()
        done.wait()
        return status
    }

    private func launch(_ process: Process, name: String, store: (Supervisor, Process) -> Void) throws {
        process.terminationHandler = { [weak self] ended in
            guard let self, !self.isStopping else { return }
            let message = "\(name) exited unexpectedly (status \(ended.terminationStatus)). Its log is "
                + "\(self.logDir.path)/\(name).log. Quit and reopen LoonInspect to start it again."
            self.log.error(message)
            self.onUnexpectedExit?(message)
        }
        lock.lock()
        defer { lock.unlock() }
        if stopping { throw ShellFailure.stopping }
        try process.run()
        store(self, process)
        log.info("started \(name), PID \(process.processIdentifier)")
    }

    // MARK: - stop

    /// The backend first (it holds connections), then Postgres with pg_ctl's fast shutdown.
    /// Safe to call more than once, from any thread, and before start() has finished.
    func stop() {
        lock.lock()
        stopping = true
        let backend = self.backend, postgres = self.postgres, ownsData = instanceLock >= 0
        lock.unlock()
        if let backend, backend.isRunning {
            log.info("stopping the backend (PID \(backend.processIdentifier))")
            backend.terminate()
            if !waitForExit(backend, seconds: 15) {
                log.error("the backend did not stop within 15 s; killing it")
                kill(backend.processIdentifier, SIGKILL)
                _ = waitForExit(backend, seconds: 5)
            }
        }
        // Without the instance lock this process never touched the database, and must not now.
        if ownsData {
            if postgres?.isRunning == true
                || FileManager.default.fileExists(atPath: pgdata.appendingPathComponent("postmaster.pid").path) {
                do { try stopPostgresCleanly() } catch { log.error("\(error)") }
            }
            if let postgres, postgres.isRunning {
                log.error("postgres is still running after pg_ctl stop; sending it SIGQUIT")
                kill(postgres.processIdentifier, SIGQUIT)
                _ = waitForExit(postgres, seconds: 10)
            }
            try? FileManager.default.removeItem(at: runDir.appendingPathComponent("port"))
        }
        lock.lock()
        if instanceLock >= 0 { close(instanceLock); instanceLock = -1 }
        lock.unlock()
        log.info("stopped")
    }

    private func stopPostgresCleanly() throws {
        let result = try runTool(bin("pg_ctl"), ["stop", "-D", pgdata.path, "-m", "fast", "-w", "-t", "30"], environment: baseEnvironment)
        log.info("pg_ctl stop -m fast: exit \(result.status) \(result.stdout.trimmingCharacters(in: .whitespacesAndNewlines))")
        if result.status != 0 && !result.stderr.contains("does not exist") {
            throw ShellFailure("pg_ctl stop failed (exit \(result.status)): \(result.stderr)")
        }
    }

    private func waitForExit(_ process: Process, seconds: Double) -> Bool {
        let deadline = Date().addingTimeInterval(seconds)
        while process.isRunning && Date() < deadline { usleep(50_000) }
        return !process.isRunning
    }

    // MARK: - for the window

    /// The first-run claim token this backend logged, if it logged one: app.core.bootstrap
    /// writes it to the log because whoever can read the log may claim the instance, and
    /// whoever runs this app can. Read from this session's part of backend.log only, since a
    /// restart mints a new token.
    func claimToken() -> String? {
        let url = logDir.appendingPathComponent("backend.log")
        guard let handle = try? FileHandle(forReadingFrom: url) else { return nil }
        defer { try? handle.close() }
        try? handle.seek(toOffset: backendLogStart)
        guard let data = try? handle.readToEnd() else { return nil }
        for line in String(decoding: data, as: UTF8.self).split(separator: "\n").reversed() where line.contains("claim token") {
            let message = (try? JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any])?["message"] as? String
            if let token = (message ?? String(line)).components(separatedBy: ": ").last?
                .trimmingCharacters(in: .whitespacesAndNewlines), !token.isEmpty, !token.contains(" ") {
                return token
            }
        }
        return nil
    }

    func tail(_ url: URL, lines: Int = 12) -> String {
        guard let text = try? String(contentsOf: url, encoding: .utf8) else { return "(no log yet)" }
        return text.split(separator: "\n", omittingEmptySubsequences: false).suffix(lines).joined(separator: "\n")
    }
}
