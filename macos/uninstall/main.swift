import Darwin
import Foundation
import Security

/// Standalone macOS reset entry point. No path/identity override and no unattended destructive mode.
final class NativeActions: UninstallActions {
    let home: String
    let uid: uid_t
    private var keychain: SecKeychain?
    init(home: String, uid: uid_t) { self.home = home; self.uid = uid }

    private func execute(_ executable: String, _ arguments: [String]) throws -> (status: Int32, output: String) {
        let process = Process(), output = Pipe()
        process.executableURL = URL(fileURLWithPath: executable); process.arguments = arguments
        process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C"]
        process.standardOutput = output; process.standardError = FileHandle.nullDevice
        try process.run()
        let bytes = output.fileHandleForReading.readDataToEndOfFile(); process.waitUntilExit()
        return (process.terminationStatus, String(decoding: bytes, as: UTF8.self))
    }
    private func run(_ executable: String, _ arguments: [String]) throws -> String {
        let result = try execute(executable, arguments)
        guard result.status == 0 else { throw UninstallFailure("\(executable) failed (status \(result.status)). Check local process access and retry; no automatic force-stop is used.") }
        return result.output
    }
    private func processes() throws -> [OwnedProcess] {
        try run("/bin/ps", ["-axo", "uid=,pid=,comm="]).split(separator: "\n").compactMap { line in
            let parts = line.split(maxSplits: 2, omittingEmptySubsequences: true, whereSeparator: { $0 == " " || $0 == "\t" })
            guard parts.count == 3, UInt32(parts[0]) == uid, let pid = Int32(parts[1]), pid != getpid() else { return nil }
            return OwnedProcess(pid: pid, executable: String(parts[2]))
        }
    }
    func validateApp(_ path: String) throws {
        do { _ = try run("/usr/bin/codesign", ["--verify", "--strict", "--requirement", "=identifier \"\(UninstallPlan.bundleID)\"", path]) }
        catch { throw UninstallFailure("The app signature/identity does not verify: \(path). Check that bundle before removing it separately, then preview again. No data or keys were removed.") }
    }
    func stopServices(plan: UninstallPlan) throws {
        let suffix = "/Contents/MacOS/LoonInspect"
        let apps = try processes().filter { $0.executable.hasSuffix(suffix) && UninstallPlan.isApp(String($0.executable.dropLast(suffix.count))) }
        for app in apps {
            let bundle = String(app.executable.dropLast(suffix.count))
            try UninstallPlan.checkAncestors(bundle)
            // Validate a sealed app identity before signalling it, including nonstandard locations.
            try validateApp(bundle)
            guard try processes().contains(app) else { continue }
            guard kill(app.pid, SIGTERM) == 0 || errno == ESRCH else { throw UninstallFailure("LoonInspect could not be stopped. Quit it normally and retry; no files or keys were removed.") }
        }
        let deadline = Date().addingTimeInterval(35)
        let roots = Set(plan.applications + apps.map { String($0.executable.dropLast(suffix.count)) })
        while true {
            let remaining = try processes().filter { process in
                apps.contains(process) || roots.contains(where: { process.executable.hasPrefix($0 + "/Contents/Resources/") })
            }
            if remaining.isEmpty { break }
            guard Date() < deadline else { throw UninstallFailure("LoonInspect services did not stop within 35 seconds. Quit the app and its MCP clients, or restart this Mac, then retry. No files or keys were removed.") }
            Thread.sleep(forTimeInterval: 0.2)
        }
        // A live PID in this cluster is a refusal, never permission to signal a reused PID.
        if let text = try? String(contentsOfFile: plan.support + "/pgdata/postmaster.pid", encoding: .utf8),
           let line = text.split(separator: "\n").first, let pid = Int32(line), pid > 1,
           kill(pid, 0) == 0 || errno == EPERM {
            throw UninstallFailure("The local database still reports a live process. Open and quit LoonInspect cleanly, or restart this Mac, then retry. Its data and keys were retained.")
        }
    }
    func prepareKeychain() throws {
        let path = home + "/Library/Keychains/login.keychain-db"
        try UninstallPlan.checkAncestors(path)
        if !FileManager.default.fileExists(atPath: path) { return }
        _ = try UninstallPlan.inspect(path, uid: uid, bundle: false)
        let status = SecKeychainOpen(path, &keychain)
        var flags: SecKeychainStatus = 0
        guard status == errSecSuccess, let keychain, SecKeychainGetStatus(keychain, &flags) == errSecSuccess,
              flags & SecKeychainStatus(kSecUnlockStateStatus) != 0 else {
            throw UninstallFailure("The login Keychain is locked or unavailable. Unlock it in Keychain Access and retry. No services, files or keys were changed.")
        }
    }
    func removeKeychainItems() throws {
        guard keychain != nil else { return }
        // The app creates its database keys with Apple's security CLI. Use that same
        // tool for deletion: a separate executable's SecItemDelete can fail its owner ACL.
        let targets: [(String, String?)] = UninstallPlan.accounts.map { ("LoonInspect", $0) } + [("io.loonsec.LoonInspect.mcp", nil)]
        let path = home + "/Library/Keychains/login.keychain-db"
        for (service, account) in targets {
            var args = ["delete-generic-password", "-s", service]
            if let account { args += ["-a", account] }
            args.append(path)
            var deleted = 0
            while true {
                let result = try execute("/usr/bin/security", args)
                if result.status == 44 { break } // errSecItemNotFound, including a rerun.
                guard result.status == 0 else {
                    throw UninstallFailure("Keychain removal failed (security status \(result.status)); removal may be partial. Unlock login Keychain and retry. If access is refused, use Keychain Access to review only the previewed service/accounts, then preview again. No secret values were printed.")
                }
                deleted += 1
                guard deleted < 10000 else { throw UninstallFailure("Keychain cleanup exceeded its item limit. Stop clients that may be pairing, review the previewed service in Keychain Access, and retry.") }
            }
        }
    }
    func clearPreferences() throws {
        let domain = UninstallPlan.bundleID as CFString
        for host in [kCFPreferencesAnyHost, kCFPreferencesCurrentHost] {
            if let keys = CFPreferencesCopyKeyList(domain, kCFPreferencesCurrentUser, host) {
                CFPreferencesSetMultiple(nil, keys, domain, kCFPreferencesCurrentUser, host)
                guard CFPreferencesSynchronize(domain, kCFPreferencesCurrentUser, host) else {
                    throw UninstallFailure("LoonInspect preferences could not be cleared. Check this user's Library permissions and retry; removal may be partial.")
                }
            }
        }
    }
}

func main() throws {
    let args = Array(CommandLine.arguments.dropFirst())
    if args == ["--help"] {
        print("Usage: LoonInspect-Uninstall [--dry-run | --uninstall]\nDefault: preview only. --uninstall requires a terminal, a backup decision and a typed permanent-removal confirmation. Never run with sudo.")
        return
    }
    guard args.isEmpty || args == ["--dry-run"] || args == ["--uninstall"] else { throw UninstallFailure("Use --dry-run or --uninstall. There is no --yes, alternate-user or custom-path mode. See --help.") }
    guard getuid() != 0, geteuid() == getuid(), let entry = getpwuid(getuid()) else { throw UninstallFailure("Run this helper as the macOS user whose local instance you intend to remove, without sudo.") }
    let user = String(cString: entry.pointee.pw_name)
    guard let resolvedHome = realpath(entry.pointee.pw_dir, nil) else { throw UninstallFailure("This account has no accessible home directory. Check the macOS account before retrying.") }
    defer { free(resolvedHome) }
    let home = String(cString: resolvedHome)
    let plan = try UninstallPlan(home: home, uid: getuid(), applications: ["/Applications/LoonInspect.app", home + "/Applications/LoonInspect.app"],
        socket: "/private/tmp/io.loonsec.looninspect.\(getuid())")
    print("LoonInspect clean uninstall — macOS user \(user) (uid \(getuid()))")
    print("Permanently removes this local instance's accounts, database, inventory, audit/diagnostic logs, web session/cache and preferences. This is not password recovery.")
    print("Stops this user's verified LoonInspect app and waits for its services to exit. No force-kill is used.")
    print("Removal paths:")
    for item in plan.removals { print("  \(item.path)") }
    print("Login Keychain: service LoonInspect, accounts \(UninstallPlan.accounts.joined(separator: ", ")); service io.loonsec.LoonInspect.mcp, all local profiles. Secret values are never read or exported.")
    print("Preserved: exports/backups outside the paths above, other users' data, remote Jamf data, custom app locations and credentials in other keychains. Standard app bundles owned by someone else are retained.")
    for path in plan.retained { print("  Retained: \(path)") }
    guard args == ["--uninstall"] else { print("Preview only: nothing was changed. Re-run with --uninstall only when ready for a permanent reset."); return }
    guard isatty(STDIN_FILENO) == 1 else { throw UninstallFailure("Permanent removal needs an interactive terminal. Run --uninstall in Terminal to review and confirm the preview.") }
    print("Before continuing, quit LoonInspect and preserve any needed pgdata backup with its matching three Keychain items. Move any backups/exports out of ALL removal paths listed above. The helper does not create a backup.")
    try confirmUninstall(user: user, read: { readLine() }, report: { print($0) })
    try executeUninstall(plan, actions: NativeActions(home: home, uid: getuid())) { print($0) }
    print("Local reset complete. Install/open the signed LoonInspect app and create a new account at first-time setup. Previous credentials and inventory are gone. Re-pair MCP clients after creating new tokens. Retained custom/shared bundles and files listed above require a separate decision.")
}
do { try main() }
catch { fputs("LoonInspect uninstall: \(error)\n", stderr); exit(1) }
