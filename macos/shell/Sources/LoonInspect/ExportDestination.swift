import Foundation

/// Downloads finish in a staging file before replacing a user-approved destination.
/// A cancelled or failed export must never destroy an earlier report.
struct ExportDestination {
    let url: URL
    let stagingURL: URL
    private let replaceExisting: Bool

    init(url: URL) {
        self.url = url
        stagingURL = url.deletingLastPathComponent().appendingPathComponent(".looninspect-\(UUID().uuidString).download")
        replaceExisting = FileManager.default.fileExists(atPath: url.path)
    }

    static func suggestedName(_ value: String) -> String {
        let name = (value as NSString).lastPathComponent
        return name.isEmpty || name == "." || name == ".." || name == "/" ? "LoonInspect-export" : name
    }

    func commit() throws {
        let fm = FileManager.default
        try fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: stagingURL.path)
        if replaceExisting && fm.fileExists(atPath: url.path) {
            _ = try fm.replaceItemAt(url, withItemAt: stagingURL)
        } else {
            // If another file appeared after the save panel, preserve it and report the conflict.
            try fm.moveItem(at: stagingURL, to: url)
        }
    }

    func discard() { try? FileManager.default.removeItem(at: stagingURL) }
}
