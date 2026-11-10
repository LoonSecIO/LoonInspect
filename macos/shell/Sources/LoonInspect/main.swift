import AppKit

// LoonInspect.app's entry point. `--headless` does everything the app does except the window
// (start, health, the same stop on SIGTERM or SIGINT), for testing from a terminal.
let supervisor = Supervisor()
// A closed stderr pipe must not kill the shell and orphan its children; the write just fails.
signal(SIGPIPE, SIG_IGN)

if CommandLine.arguments.contains("--headless") {
    var signalSources: [DispatchSourceSignal] = []
    for sig in [SIGTERM, SIGINT, SIGHUP] {
        signal(sig, SIG_IGN)
        let source = DispatchSource.makeSignalSource(signal: sig, queue: .global())
        source.setEventHandler {
            supervisor.log.info("signal \(sig): stopping")
            supervisor.stop()
            exit(0)
        }
        source.resume()
        signalSources.append(source)
    }
    supervisor.onUnexpectedExit = { _ in
        supervisor.stop()
        exit(1)
    }
    DispatchQueue.global(qos: .userInitiated).async {
        do {
            let port = try supervisor.start()
            print("LoonInspect is up at http://127.0.0.1:\(port)/ (SIGTERM or Ctrl-C stops it)")
            fflush(stdout)
        } catch {
            guard !supervisor.isStopping else { return }
            supervisor.log.error("\(error)")
            supervisor.stop()
            exit(1)
        }
    }
    withExtendedLifetime(signalSources) { dispatchMain() }
} else {
    // Top-level code runs on the main thread; say so, since the delegate is main-actor isolated.
    MainActor.assumeIsolated {
        let app = NSApplication.shared
        let delegate = AppDelegate(supervisor: supervisor)
        app.delegate = delegate
        app.setActivationPolicy(.regular)
        app.run()
    }
}
