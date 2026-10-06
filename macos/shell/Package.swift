// swift-tools-version:5.10
// The LoonInspect.app shell: a window around the backend's own UI, and the supervisor that
// starts and stops the embedded Postgres and the backend. Built by macos/scripts/build-app.sh.
import PackageDescription

let package = Package(
    name: "LoonInspectShell",
    platforms: [.macOS(.v13)],
    targets: [
        .executableTarget(name: "LoonInspect", path: "Sources/LoonInspect")
    ]
)
