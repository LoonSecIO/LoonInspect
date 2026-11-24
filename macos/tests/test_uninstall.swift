import Darwin
import Foundation

final class FakeActions: UninstallActions {
    var calls: [String] = []
    var fail: String?
    var onClearPreferences: (() throws -> Void)?
    func step(_ name: String) throws { calls.append(name); if fail == name { throw UninstallFailure("Synthetic \(name) refusal") } }
    func validateApp(_ path: String) throws { try step("identity") }
    func prepareKeychain() throws { try step("prepare") }
    func stopServices(plan: UninstallPlan) throws { try step("stop") }
    func removeKeychainItems() throws { try step("keys") }
    func clearPreferences() throws { try step("preferences"); try onClearPreferences?() }
    func removeItem(at path: String) throws { try step("remove"); try FileManager.default.removeItem(atPath: path) }
}

@main struct UninstallTests {
    static let fm = FileManager.default
    static func check(_ value: @autoclosure () -> Bool, _ message: String) { if !value() { fatalError(message) } }
    static func refused(_ block: () throws -> Void) { do { try block(); fatalError("Expected refusal") } catch {} }
    static func write(_ path: String, _ value: String = "synthetic") throws {
        try fm.createDirectory(atPath: (path as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
        try value.write(toFile: path, atomically: true, encoding: .utf8)
    }
    static func app(_ path: String, identifier: String = UninstallPlan.bundleID) throws {
        let info = ["CFBundleIdentifier": identifier, "CFBundleExecutable": "LoonInspect", "CFBundlePackageType": "APPL"]
        try fm.createDirectory(atPath: path + "/Contents", withIntermediateDirectories: true)
        try PropertyListSerialization.data(fromPropertyList: info, format: .xml, options: 0).write(to: URL(fileURLWithPath: path + "/Contents/Info.plist"))
    }
    static func main() throws {
        guard let temporary = realpath(fm.temporaryDirectory.path, nil) else { fatalError("Temporary directory unavailable") }
        defer { free(temporary) }
        let root = String(cString: temporary) + "/looninspect-uninstall-tests-" + UUID().uuidString
        try fm.createDirectory(atPath: root, withIntermediateDirectories: true)
        defer { try? fm.removeItem(atPath: root) }
        var passed = 0
        func fixture(_ name: String) throws -> (String, String, String) {
            let home = root + "/" + name
            try fm.createDirectory(atPath: home, withIntermediateDirectories: true)
            return (home, home + "/Library/Application Support/LoonInspect", home + "/socket")
        }
        func plan(_ home: String, _ socket: String) throws -> UninstallPlan {
            try UninstallPlan(home: home, uid: getuid(), applications: [home + "/Applications/LoonInspect.app"], socket: socket)
        }
        // Dry planning has no actions/mutations, and the destructive engine only removes its allowlist.
        do {
            let (home, support, socket) = try fixture("clean")
            try write(support + "/pgdata/PG_VERSION", "17"); try write(support + "/logs/backend.log")
            try write(support + "/data/audit/synthetic/audit.jsonl"); try write(support + "/run/port")
            try write(home + "/Documents/evidence.pdf"); try write(support + "/backup/PG_VERSION")
            try write(support + "/data/export.pdf"); try app(home + "/Applications/LoonInspect.app")
            let browserPaths = ["HTTPStorages/io.loonsec.looninspect/store", "HTTPStorages/io.loonsec.looninspect.binarycookies",
                                "Cookies/io.loonsec.looninspect.binarycookies", "Preferences/ByHost/io.loonsec.looninspect.12345678-ABCD-1234-ABCD-123456789ABC.plist"]
            for path in browserPaths { try write(home + "/Library/" + path) }
            let unrelatedPreferences = home + "/Library/Preferences/ByHost/io.loonsec.looninspect-other.synthetic.plist"
            try write(unrelatedPreferences)
            let preview = try plan(home, socket)
            check(fm.fileExists(atPath: support + "/pgdata/PG_VERSION"), "Preview removed data")
            let actions = FakeActions(); try executeUninstall(preview, actions: actions) { _ in }
            check(Array(actions.calls.prefix(4)) == ["identity", "prepare", "stop", "preferences"] && actions.calls.firstIndex(of: "keys")! > actions.calls.firstIndex(of: "remove")!, "Unsafe operation order")
            check(!fm.fileExists(atPath: support + "/pgdata"), "Database retained")
            check(!fm.fileExists(atPath: home + "/Applications/LoonInspect.app"), "Verified app retained")
            for path in browserPaths { check(!fm.fileExists(atPath: home + "/Library/" + path), "Bundle web/preferences state retained") }
            check(fm.fileExists(atPath: unrelatedPreferences), "Other bundle preferences removed")
            for path in [home + "/Documents/evidence.pdf", support + "/backup/PG_VERSION", support + "/data/export.pdf"] {
                check(fm.fileExists(atPath: path), "Backup/export removed")
            }
            try executeUninstall(plan(home, socket), actions: FakeActions()) { _ in }
            passed += 1
        }
        do {
            let (home, _, socket) = try fixture("preferences-domain-boundary")
            let preferences = home + "/Library/Preferences/"
            let uuid = "12345678-ABCD-1234-ABCD-123456789ABC"
            let own = [UninstallPlan.bundleID + ".plist"]
                + [uuid, "23456789-abcd-1234-abcd-123456789abc", "001122aabbcc", "AABBCCDDEEFF", "UnknownHostID"].map {
                    "ByHost/" + UninstallPlan.bundleID + "." + $0 + ".plist"
                }
            let retained = [
                "ByHost/" + UninstallPlan.bundleID + ".beta." + uuid + ".plist",
                "ByHost/" + UninstallPlan.bundleID + "-other." + uuid + ".plist",
                "ByHost/example.unrelated." + uuid + ".plist",
                "ByHost/" + UninstallPlan.bundleID + ".backup.plist",
                "ByHost/" + UninstallPlan.bundleID + "..plist",
                "ByHost/" + UninstallPlan.bundleID + ".123456789ABCDEF.plist",
            ]
            for path in own + retained { try write(preferences + path) }
            let preview = try plan(home, socket)
            check(Set(preview.removals.map { $0.path }) == Set(own.map { preferences + $0 }), "Preview crossed a preference domain boundary")
            try executeUninstall(preview, actions: FakeActions()) { _ in }
            for path in own { check(!fm.fileExists(atPath: preferences + path), "Own host/any-host preferences retained") }
            for path in retained { check(fm.fileExists(atPath: preferences + path), "Other preference domain or unknown file removed") }
            passed += 1
        }
        do {
            let (home, _, socket) = try fixture("rewritten-preferences")
            let path = home + "/Library/Preferences/ByHost/io.loonsec.looninspect.12345678-ABCD-1234-ABCD-123456789ABC.plist"
            try write(path)
            let preview = try plan(home, socket), actions = FakeActions()
            actions.onClearPreferences = { try fm.removeItem(atPath: path); try write(path, "rewritten") }
            try executeUninstall(preview, actions: actions) { _ in }
            check(!fm.fileExists(atPath: path), "Synchronized preferences retained")
            passed += 1
        }
        do {
            let (home, _, socket) = try fixture("redirected-byhost")
            try write(home + "/outside/io.loonsec.looninspect.12345678-ABCD-1234-ABCD-123456789ABC.plist")
            try fm.createDirectory(atPath: home + "/Library/Preferences", withIntermediateDirectories: true)
            try fm.createSymbolicLink(atPath: home + "/Library/Preferences/ByHost", withDestinationPath: home + "/outside")
            refused { _ = try plan(home, socket) }
            check(fm.fileExists(atPath: home + "/outside/io.loonsec.looninspect.12345678-ABCD-1234-ABCD-123456789ABC.plist"), "Redirected preferences touched")
            passed += 1
        }
        do {
            let (home, support, socket) = try fixture("symlink")
            try write(home + "/outside/keep")
            try fm.createDirectory(atPath: (support as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
            try fm.createSymbolicLink(atPath: support, withDestinationPath: home + "/outside")
            refused { _ = try plan(home, socket) }; check(fm.fileExists(atPath: home + "/outside/keep"), "Symlink target touched")
            passed += 1
        }
        do {
            let (home, support, socket) = try fixture("nested-symlink")
            try write(home + "/outside/keep"); try write(support + "/logs/file")
            try fm.createSymbolicLink(atPath: support + "/logs/link", withDestinationPath: home + "/outside")
            try executeUninstall(plan(home, socket), actions: FakeActions()) { _ in }
            check(fm.fileExists(atPath: home + "/outside/keep"), "Recursive removal followed a link")
            passed += 1
        }
        do {
            let (home, _, socket) = try fixture("wrong-app")
            try app(home + "/Applications/LoonInspect.app", identifier: "example.unrelated")
            let preview = try plan(home, socket); check(preview.removals.isEmpty && preview.retained.count == 1, "Wrong bundle included")
            try executeUninstall(preview, actions: FakeActions()) { _ in }
            check(fm.fileExists(atPath: home + "/Applications/LoonInspect.app"), "Wrong bundle removed")
            passed += 1
        }
        for mutation in ["replace", "new", "link"] {
            let (home, support, socket) = try fixture(mutation)
            try write(support + "/logs/file")
            let preview = try plan(home, socket)
            if mutation == "new" { try write(support + "/pgdata/PG_VERSION") }
            else {
                try fm.moveItem(atPath: support + "/logs", toPath: home + "/old-logs")
                if mutation == "replace" { try write(support + "/logs/file") }
                else { try fm.createSymbolicLink(atPath: support + "/logs", withDestinationPath: home + "/old-logs") }
            }
            let actions = FakeActions(); refused { try executeUninstall(preview, actions: actions) { _ in } }
            check(actions.calls.isEmpty, "Changed preview performed native actions"); passed += 1
        }
        for failure in ["identity", "prepare", "stop", "preferences", "remove"] {
            let (home, support, socket) = try fixture(failure)
            try write(support + "/pgdata/PG_VERSION")
            try app(home + "/Applications/LoonInspect.app")
            let actions = FakeActions(); actions.fail = failure
            refused { try executeUninstall(plan(home, socket), actions: actions) { _ in } }
            check(!actions.calls.contains("keys") && fm.fileExists(atPath: support + "/pgdata/PG_VERSION"), "Refusal destroyed data/keys")
            passed += 1
        }
        do {
            let (home, support, socket) = try fixture("locked")
            try write(support + "/run/shell.lock"); try write(support + "/pgdata/PG_VERSION")
            let fd = open(support + "/run/shell.lock", O_RDWR); check(fd >= 0 && flock(fd, LOCK_EX | LOCK_NB) == 0, "Test lock failed")
            defer { close(fd) }
            let actions = FakeActions(); refused { try executeUninstall(plan(home, socket), actions: actions) { _ in } }
            check(!actions.calls.contains("keys") && fm.fileExists(atPath: support + "/pgdata/PG_VERSION"), "Locked instance removed")
            passed += 1
        }
        for responses: [String?] in [[nil], ["wrong"], ["BACKUP SAVED", nil], ["NO BACKUP NEEDED", "DELETE LoonInspect for someone-else"]] {
            var answers = responses
            refused { try confirmUninstall(user: "synthetic", read: { answers.removeFirst() }, report: { _ in }) }
            passed += 1
        }
        for decision in ["BACKUP SAVED", "NO BACKUP NEEDED"] {
            var answers = [decision, "DELETE LoonInspect for synthetic"]
            try confirmUninstall(user: "synthetic", read: { answers.removeFirst() }, report: { _ in })
            passed += 1
        }
        print("PASS: \(passed) isolated uninstall scenarios; no host Keychain, services or app data touched")
    }
}
