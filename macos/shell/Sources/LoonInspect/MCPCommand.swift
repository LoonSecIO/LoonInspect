import Darwin
import Foundation
import Security

/// The app's MCP commands: pair a named client in Keychain, or attach its stdio to the local server.
/// Runs before Supervisor exists, so a client connection cannot start a second database or window.
enum MCPCommand {
    private static let service = "io.loonsec.LoonInspect.mcp"

    static func handleIfRequested() {
        let args = Array(CommandLine.arguments.dropFirst())
        guard args.contains("--mcp") || args.contains("--mcp-pair") else { return }
        do {
            guard args.count == 3, ["--mcp", "--mcp-pair"].contains(args[0]), args[1] == "--profile",
                  validProfile(args[2]) else {
                throw ShellFailure("Use --mcp or --mcp-pair followed by --profile and a name containing 1–64 letters, digits, '-' or '_'.")
            }
            if args[0] == "--mcp-pair" {
                try pair(profile: args[2])
                stderr("Saved the MCP credential for \(args[2]) in this Mac's login keychain. Open LoonInspect before connecting.")
                exit(0)
            }
            try launch(profile: args[2])
        } catch {
            stderr("LoonInspect MCP: \(error)")
            exit(1)
        }
    }

    static func validProfile(_ value: String) -> Bool {
        (1...64).contains(value.count) && value.utf8.allSatisfy {
            (65...90).contains($0) || (97...122).contains($0) || (48...57).contains($0) || $0 == 45 || $0 == 95
        }
    }

    static func validToken(_ value: String) -> Bool {
        value.count <= 4096 && value.range(of: "^loon_pat_[a-f0-9]{32}_[A-Za-z0-9_-]+$", options: .regularExpression) != nil
    }

    private static func stderr(_ text: String) {
        try? FileHandle.standardError.write(contentsOf: Data((text + "\n").utf8))
    }

    private static func query(profile: String) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: service,
         kSecAttrAccount as String: profile]
    }

    private static func pair(profile: String) throws {
        let token: String
        if isatty(STDIN_FILENO) == 1 {
            guard let value = getpass("Paste the MCP token (hidden): ") else {
                throw ShellFailure("The token could not be read. Run pairing from a terminal or supply it on standard input.")
            }
            token = String(cString: value).trimmingCharacters(in: .whitespacesAndNewlines)
        } else {
            let bytes = FileHandle.standardInput.readData(ofLength: 4097)
            guard bytes.count <= 4096, let value = String(data: bytes, encoding: .utf8) else {
                throw ShellFailure("The token is invalid. Copy the newly created MCP token and pair again.")
            }
            token = value.trimmingCharacters(in: .whitespacesAndNewlines)
        }
        guard validToken(token) else {
            throw ShellFailure("The token is invalid. Copy the newly created MCP token and pair again.")
        }
        let value = [kSecValueData as String: Data(token.utf8)]
        let existing = query(profile: profile)
        var status = SecItemUpdate(existing as CFDictionary, value as CFDictionary)
        if status == errSecItemNotFound {
            var item = existing.merging(value) { _, new in new }
            item[kSecAttrLabel as String] = "LoonInspect MCP: \(profile)"
            item[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            status = SecItemAdd(item as CFDictionary, nil)
        }
        guard status == errSecSuccess else {
            throw ShellFailure("The MCP credential could not be saved (Keychain status \(status)). Unlock the login keychain and pair again.")
        }
    }

    private static func credential(profile: String) throws -> Data {
        var item = query(profile: profile)
        item[kSecReturnData as String] = true
        item[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(item as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data,
              let token = String(data: data, encoding: .utf8), validToken(token) else {
            throw ShellFailure("No usable MCP credential was found for '\(profile)' (Keychain status \(status)). Unlock the login keychain or run --mcp-pair --profile \(profile).")
        }
        return data
    }

    private static func launch(profile: String) throws {
        guard let resources = Bundle.main.resourceURL else { throw ShellFailure("Run MCP from the installed LoonInspect.app bundle.") }
        let python = resources.appendingPathComponent("python/bin/python3")
        let launcher = resources.appendingPathComponent("launcher/loon_mcp.py")
        guard FileManager.default.isExecutableFile(atPath: python.path), FileManager.default.fileExists(atPath: launcher.path) else {
            throw ShellFailure("This app bundle does not contain the MCP adapter. Install a build that includes MCP support.")
        }
        let token = try credential(profile: profile)
        var descriptors: [Int32] = [0, 0]
        guard pipe(&descriptors) == 0 else { throw ShellFailure("The MCP credential pipe could not be opened. Reconnect this client.") }
        let reader = descriptors[0], writer = FileHandle(fileDescriptor: descriptors[1], closeOnDealloc: true)
        defer { close(reader) }
        try writer.write(contentsOf: token)
        try writer.close()
        // exec replaces this signed entry point; only the read end survives, carrying no
        // secret in argv, the environment, client configuration, logs, or a temporary file.
        guard fcntl(reader, F_SETFD, 0) == 0 else { throw ShellFailure("The MCP credential pipe could not be handed to its adapter.") }
        let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("LoonInspect/run/mcp.json")
        let arguments = [python.path, "-I", "-B", launcher.path, "--token-fd", String(reader), "--runtime", support.path]
        var environment = Supervisor.baseEnvironment(ProcessInfo.processInfo.environment)
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        let argv = arguments.map { strdup($0) } + [nil]
        let envp = environment.map { strdup("\($0.key)=\($0.value)") } + [nil]
        defer { for entry in argv + envp { free(entry) } }
        argv.withUnsafeBufferPointer { args in
            envp.withUnsafeBufferPointer { env in
                _ = execve(python.path, args.baseAddress!, env.baseAddress!)
            }
        }
        throw ShellFailure("The bundled MCP adapter could not start: \(String(cString: strerror(errno))). Reinstall LoonInspect and reconnect.")
    }
}
