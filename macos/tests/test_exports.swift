import Foundation

@main
struct ExportTests {
    static func require(_ condition: @autoclosure () throws -> Bool, _ message: String) throws {
        if try !condition() { throw NSError(domain: "ExportTests", code: 1, userInfo: [NSLocalizedDescriptionKey: message]) }
    }

    static func main() throws {
        let fm = FileManager.default
        let root = fm.temporaryDirectory.appendingPathComponent("looninspect-export-tests-\(UUID())")
        try fm.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? fm.removeItem(at: root) }
        try require(ExportDestination.suggestedName("../../report.csv") == "report.csv", "Strip suggested paths")
        try require(ExportDestination.suggestedName("..") == "LoonInspect-export", "Reject dot filenames")
        let target = root.appendingPathComponent("report.csv")
        try "previous report".write(to: target, atomically: true, encoding: .utf8)
        let cancelled = ExportDestination(url: target)
        try "partial".write(to: cancelled.stagingURL, atomically: true, encoding: .utf8)
        cancelled.discard()
        try require(try String(contentsOf: target, encoding: .utf8) == "previous report", "Cancellation preserves original")
        try require(!fm.fileExists(atPath: cancelled.stagingURL.path), "Cancellation removes partial file")
        let replacement = ExportDestination(url: target)
        try "complete report".write(to: replacement.stagingURL, atomically: true, encoding: .utf8)
        try require(try String(contentsOf: target, encoding: .utf8) == "previous report", "Original survives pending transfer")
        try replacement.commit()
        try require(try String(contentsOf: target, encoding: .utf8) == "complete report", "Successful transfer replaces approved destination")
        let conflictTarget = root.appendingPathComponent("conflict.csv")
        let conflict = ExportDestination(url: conflictTarget)
        try "new download".write(to: conflict.stagingURL, atomically: true, encoding: .utf8)
        try "unrelated file".write(to: conflictTarget, atomically: true, encoding: .utf8)
        var refused = false
        do { try conflict.commit() } catch { refused = true }
        try require(refused, "Refuse an unapproved overwrite")
        try require(try String(contentsOf: conflictTarget, encoding: .utf8) == "unrelated file", "Preserve concurrent file")
        try require(fm.fileExists(atPath: conflict.stagingURL.path), "Keep complete download recoverable after save failure")
        let permissions = try fm.attributesOfItem(atPath: conflict.stagingURL.path)[.posixPermissions] as? NSNumber
        try require(permissions?.intValue == 0o600, "Exports are readable only by their owner")
        print("Export filename, cancellation, replacement, conflict and permissions checks passed")
    }
}
