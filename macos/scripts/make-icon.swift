// Renders LoonInspect.icns from the brand mark, so no binary icon lives in the repository: the
// reversed (paper) loon on a lake-blue rounded square, on Apple's macOS icon grid (an 824 pt tile
// on a 1024 pt canvas), at every size iconutil wants. The colours are loon-design v0.1.0's `lake`
// and the mark's own (frontend/src/brand/tokens.json; frontend/public/brand/BRAND-USAGE.md).
//
//   swiftc -O -o build/make-icon macos/scripts/make-icon.swift
//   build/make-icon frontend/public/brand/loon-mark-reversed.svg build/LoonInspect.icns build
import AppKit

let arguments = CommandLine.arguments
guard arguments.count == 4 else {
    FileHandle.standardError.write(Data("usage: make-icon <mark.svg> <out.icns> <scratch directory>\n".utf8))
    exit(2)
}
let (markPath, icnsPath, scratch) = (arguments[1], arguments[2], arguments[3])
guard let mark = NSImage(contentsOfFile: markPath) else {
    FileHandle.standardError.write(Data("make-icon: AppKit could not load \(markPath)\n".utf8))
    exit(1)
}

func render(_ pixels: Int) -> Data {
    let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: pixels, pixelsHigh: pixels, bitsPerSample: 8,
                               samplesPerPixel: 4, hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB,
                               bytesPerRow: 0, bitsPerPixel: 0)!
    rep.size = NSSize(width: pixels, height: pixels)
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
    NSGraphicsContext.current?.imageInterpolation = .high
    let scale = CGFloat(pixels) / 1024
    let tile = NSRect(x: 100 * scale, y: 100 * scale, width: 824 * scale, height: 824 * scale)
    NSColor(srgbRed: 0x17 / 255, green: 0x3A / 255, blue: 0x52 / 255, alpha: 1).setFill()
    NSBezierPath(roundedRect: tile, xRadius: 185 * scale, yRadius: 185 * scale).fill()
    // The mark 560 pt across, centred: clear space of 132 pt on each side, well over the guide's minimum.
    mark.draw(in: NSRect(x: 232 * scale, y: 232 * scale, width: 560 * scale, height: 560 * scale),
              from: .zero, operation: .sourceOver, fraction: 1)
    NSGraphicsContext.restoreGraphicsState()
    return rep.representation(using: .png, properties: [:])!
}

do {
    let iconset = URL(fileURLWithPath: scratch, isDirectory: true).appendingPathComponent("LoonInspect.iconset", isDirectory: true)
    try? FileManager.default.removeItem(at: iconset)
    try FileManager.default.createDirectory(at: iconset, withIntermediateDirectories: true)
    for points in [16, 32, 128, 256, 512] {
        try render(points).write(to: iconset.appendingPathComponent("icon_\(points)x\(points).png"))
        try render(points * 2).write(to: iconset.appendingPathComponent("icon_\(points)x\(points)@2x.png"))
    }
    let iconutil = Process()
    iconutil.executableURL = URL(fileURLWithPath: "/usr/bin/iconutil")
    iconutil.arguments = ["-c", "icns", iconset.path, "-o", icnsPath]
    try iconutil.run()
    iconutil.waitUntilExit()
    exit(iconutil.terminationStatus)
} catch {
    FileHandle.standardError.write(Data("make-icon: \(error)\n".utf8))
    exit(1)
}
