import Darwin
import Foundation

/// The uninstall helper's bounded removal plan; tests supply only disposable home directories.
struct UninstallFailure: Error, CustomStringConvertible {
    let description: String
    init(_ description: String) { self.description = description }
}

struct Removal: Equatable {
    let path: String
    let device: dev_t
    let inode: ino_t
    let bundle: Bool
}

struct UninstallPlan {
    static let bundleID = "io.loonsec.looninspect"
    static let accounts = ["ENCRYPTION_KEY", "postgres-looninspect_app", "postgres-looninspect"]
    let home: String
    let uid: uid_t
    let support: String
    let socket: String
    let applications: [String]
    let removals: [Removal]
    let retained: [String]

    init(home: String, uid: uid_t, applications: [String], socket: String) throws {
        self.home = home; self.uid = uid; self.applications = applications; self.socket = socket
        let support = home + "/Library/Application Support/LoonInspect"
        self.support = support
        let fm = FileManager.default
        _ = try Self.inspect(support, uid: uid, bundle: false)
        var removals: [Removal] = [], retained: [String] = []
        // Named runtime directories only. A sibling backup/export, even under the support
        // directory, is retained. Symlinks inside a removed directory are unlinked, never followed.
        var paths = ["pgdata", "pgdata.initdb", "logs", "data/audit", "data/sofa", "data/certs", "preferred-port", "run"].map { support + "/" + $0 }
            + [home + "/Library/WebKit/" + Self.bundleID, home + "/Library/Caches/" + Self.bundleID,
               home + "/Library/HTTPStorages/" + Self.bundleID,
               home + "/Library/HTTPStorages/" + Self.bundleID + ".binarycookies",
               home + "/Library/Cookies/" + Self.bundleID + ".binarycookies",
               home + "/Library/Preferences/" + Self.bundleID + ".plist",
               home + "/Library/Saved Application State/" + Self.bundleID + ".savedState", socket]
        let byHost = home + "/Library/Preferences/ByHost"
        try Self.checkAncestors(byHost)
        if fm.fileExists(atPath: byHost) {
            let names: [String]
            do { names = try fm.contentsOfDirectory(atPath: byHost) }
            catch { throw UninstallFailure("Cannot inspect this user's ByHost preferences. Check Library access and retry; no changes were made.") }
            paths += names.filter(Self.isByHostPreference).sorted().map { byHost + "/" + $0 }
        }
        for path in paths {
            if let entry = try Self.inspect(path, uid: uid, bundle: false) { removals.append(entry) }
        }
        for path in applications {
            guard fm.fileExists(atPath: path) || Self.isLink(path) else { continue }
            do {
                guard Self.isApp(path), let entry = try Self.inspect(path, uid: uid, bundle: true) else {
                    retained.append("\(path) (bundle identity does not match)"); continue
                }
                removals.append(entry)
            } catch { retained.append("\(path) (not a safe app bundle owned by this user)") }
        }
        for directory in [support, support + "/data"] {
            try Self.checkAncestors(directory)
            if let names = try? fm.contentsOfDirectory(atPath: directory) {
                for name in names {
                    let path = directory + "/" + name
                    if !paths.contains(path) && path != support + "/data" { retained.append(path) }
                }
            }
        }
        self.removals = removals; self.retained = retained
    }

    static func isByHostPreference(_ name: String) -> Bool {
        let prefix = bundleID + ".", suffix = ".plist"
        guard name.hasPrefix(prefix), name.hasSuffix(suffix) else { return false }
        let host = String(name.dropFirst(prefix.count).dropLast(suffix.count))
        // CoreFoundation uses a UUID, a legacy 12-hex host ID, or UnknownHostID.
        // A dotted suffix belongs to another application domain, not this bundle.
        if host == "UnknownHostID" { return true }
        if let uuid = UUID(uuidString: host), uuid.uuidString.caseInsensitiveCompare(host) == .orderedSame { return true }
        return host.utf8.count == 12 && host.utf8.allSatisfy {
            (48...57).contains($0) || (65...70).contains($0) || (97...102).contains($0)
        }
    }

    static func isLink(_ path: String) -> Bool {
        var info = stat()
        return lstat(path, &info) == 0 && info.st_mode & S_IFMT == S_IFLNK
    }

    static func checkAncestors(_ path: String) throws {
        // Keep the literal, canonical filesystem path supplied by the entry point;
        // Foundation temporary-directory URLs can retain the /var system symlink.
        var cursor = path
        while cursor != "/" && !cursor.isEmpty {
            if isLink(cursor) { throw UninstallFailure("Refusing a symbolic-link path: \(cursor). Move the link aside and check its destination before retrying.") }
            cursor = (cursor as NSString).deletingLastPathComponent
        }
    }

    static func inspect(_ path: String, uid: uid_t, bundle: Bool) throws -> Removal? {
        try checkAncestors(path)
        var info = stat()
        if lstat(path, &info) != 0 {
            if errno == ENOENT { return nil }
            throw UninstallFailure("Cannot inspect \(path). Check this user's access and retry.")
        }
        guard info.st_uid == uid, [S_IFDIR, S_IFREG].contains(info.st_mode & S_IFMT) else {
            throw UninstallFailure("Refusing \(path): it is not a regular file or directory owned by this user. Check ownership; do not run this helper with sudo.")
        }
        return Removal(path: path, device: info.st_dev, inode: info.st_ino, bundle: bundle)
    }

    static func isApp(_ path: String) -> Bool {
        guard !isLink(path),
              let data = FileManager.default.contents(atPath: path + "/Contents/Info.plist"),
              let info = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] else { return false }
        return info["CFBundleIdentifier"] as? String == bundleID
            && info["CFBundleExecutable"] as? String == "LoonInspect"
            && info["CFBundlePackageType"] as? String == "APPL"
    }

    func verify(_ removal: Removal) throws {
        guard let current = try Self.inspect(removal.path, uid: uid, bundle: removal.bundle), current == removal,
              !removal.bundle || Self.isApp(removal.path) else {
            throw UninstallFailure("\(removal.path) changed after the preview. Nothing else will be removed; run a new preview.")
        }
    }
}

struct OwnedProcess: Equatable {
    let pid: Int32
    let executable: String
}

protocol UninstallActions {
    func validateApp(_ path: String) throws
    func stopServices(plan: UninstallPlan) throws
    func prepareKeychain() throws
    func removeKeychainItems() throws
    func clearPreferences() throws
    func removeItem(at path: String) throws
}

extension UninstallActions {
    func removeItem(at path: String) throws { try FileManager.default.removeItem(atPath: path) }
}

func confirmUninstall(user: String, read: () -> String?, report: (String) -> Void) throws {
    report("Type BACKUP SAVED or NO BACKUP NEEDED:")
    guard let decision = read(), ["BACKUP SAVED", "NO BACKUP NEEDED"].contains(decision) else { throw UninstallFailure("Cancelled: no changes made.") }
    let confirmation = "DELETE LoonInspect for \(user)"
    report("Type exactly: \(confirmation)")
    guard read() == confirmation else { throw UninstallFailure("Cancelled: no changes made.") }
}

/// Executes only an already-previewed plan. Native service/keychain actions have a fake test counterpart.
func executeUninstall(_ plan: UninstallPlan, actions: UninstallActions, report: (String) -> Void) throws {
    // Recheck every identity before any service, Keychain or filesystem mutation.
    let fresh = try UninstallPlan(home: plan.home, uid: plan.uid, applications: plan.applications, socket: plan.socket)
    guard fresh.removals == plan.removals else { throw UninstallFailure("The removal paths changed after the preview. Run a new preview; nothing has been changed.") }
    for entry in plan.removals { try plan.verify(entry) }
    for entry in plan.removals where entry.bundle { try actions.validateApp(entry.path) }
    try actions.prepareKeychain()
    try actions.stopServices(plan: plan)
    let afterStop = try UninstallPlan(home: plan.home, uid: plan.uid, applications: plan.applications, socket: plan.socket)
    guard afterStop.removals == plan.removals else { throw UninstallFailure("The runtime paths changed during shutdown. Run a new preview before removing data or keys.") }
    let runDir = plan.support + "/run"
    let lockPath = runDir + "/shell.lock"
    let createdRun = !FileManager.default.fileExists(atPath: runDir)
    try UninstallPlan.checkAncestors(lockPath)
    // Hold the same lock even if a previous launch never created run/. A concurrent app
    // must fail its instance check before either process can use/reset the database.
    try FileManager.default.createDirectory(atPath: runDir, withIntermediateDirectories: true,
                                           attributes: [.posixPermissions: 0o700])
    _ = try UninstallPlan.inspect(runDir, uid: plan.uid, bundle: false)
    let lockFD = open(lockPath, O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0o600)
    var lockInfo = stat()
    guard lockFD >= 0, fstat(lockFD, &lockInfo) == 0, lockInfo.st_uid == plan.uid,
          lockInfo.st_mode & S_IFMT == S_IFREG, lockInfo.st_nlink == 1,
          flock(lockFD, LOCK_EX | LOCK_NB) == 0 else {
        if lockFD >= 0 { close(lockFD) }
        throw UninstallFailure("The local instance is still locked or its lock is unsafe. Quit LoonInspect, wait for shutdown, and retry. No data or keys were removed.")
    }
    defer {
        if createdRun {
            var current = stat()
            if lstat(lockPath, &current) == 0 && current.st_ino == lockInfo.st_ino && current.st_dev == lockInfo.st_dev { _ = unlink(lockPath) }
            _ = rmdir(runDir)
        }
        close(lockFD)
        // Empty containers only: unknown files and backups survive failures and success.
        _ = rmdir(plan.support + "/data")
        _ = rmdir(plan.support)
    }
    for entry in plan.removals { try plan.verify(entry) }
    // Keep recoverable database keys until data and preference removal has succeeded.
    // App removal and run/ (which holds the instance lock) are last.
    try actions.clearPreferences()
    func remove(_ entry: Removal) throws {
        let preferences = plan.home + "/Library/Preferences/"
        if entry.path == preferences + UninstallPlan.bundleID + ".plist"
            || (entry.path.hasPrefix(preferences + "ByHost/")
                && UninstallPlan.isByHostPreference((entry.path as NSString).lastPathComponent)) {
            // CFPreferences may remove or rewrite a previewed plist while synchronizing.
            guard try UninstallPlan.inspect(entry.path, uid: plan.uid, bundle: false) != nil else { return }
        } else { try plan.verify(entry) }
        do { try actions.removeItem(at: entry.path); report("Removed \(entry.path)") }
        catch { throw UninstallFailure("Could not remove \(entry.path). Removal may be partial; check permissions, then run a new preview and retry. Do not use sudo.") }
    }
    for entry in plan.removals where !entry.bundle && entry.path != runDir { try remove(entry) }
    try actions.removeKeychainItems()
    report("Removed this user's LoonInspect database keys and MCP credentials.")
    for entry in plan.removals where entry.bundle { try remove(entry) }
    for entry in plan.removals where entry.path == runDir { try remove(entry) }
}
