//  WatermarkTile.swift
//  Kilit — Security/ (WP6), §5.9.
//
//  Turns the integer delta map (`WatermarkPayload.deltaMap(scale:)`, WP5, passed
//  in as a raw `[Int8]`) into two OPAQUE BGRA `CGImage`s:
//    lighter  L = max(0, Δ)        in all three colour channels, alpha 255
//    darker   D = 255 − max(0, −Δ) in all three colour channels, alpha 255
//  With opaque sources `plusLighter` gives dst + L/255 and `plusDarker` gives
//  dst + D/255 − 1 = dst − max(0, −Δ)/255 exactly. WP8 caches the pair per
//  (payload, displayScale). No Crypto/ import: the Bool matrix never reaches here.

import CoreGraphics
import Foundation

enum WatermarkTile {

    /// Tile edge in points (6 cells × 28 pt, §5.9).
    static let sidePoints: CGFloat = 168

    /// Builds the lighter/darker pair from a row-major `width × height` map with
    /// values in [−5, 5]. `scale` is the display scale the map was generated for
    /// (`width == 168 · scale`); a CGImage carries no scale, so it is informational
    /// for the caller's cache key and for `UIImage(cgImage:scale:orientation:)`.
    static func make(delta: [Int8], width: Int, height: Int, scale: CGFloat)
        -> (lighter: CGImage, darker: CGImage) {
        precondition(width > 0 && height > 0, "WatermarkTile: empty map")
        precondition(delta.count == width * height, "WatermarkTile: map size mismatch")
        _ = scale

        let pixelCount: Int = width * height
        var lighterBytes: [UInt8] = [UInt8](repeating: 255, count: 4 * pixelCount)
        var darkerBytes: [UInt8] = [UInt8](repeating: 255, count: 4 * pixelCount)
        for i in 0..<pixelCount {
            let d: Int = Int(delta[i])
            let l: UInt8 = UInt8(max(0, d))
            let k: UInt8 = UInt8(255 - max(0, -d))
            let o: Int = 4 * i
            lighterBytes[o] = l          // B
            lighterBytes[o + 1] = l      // G
            lighterBytes[o + 2] = l      // R
            lighterBytes[o + 3] = 255    // X (ignored: noneSkipFirst in little-endian order)
            darkerBytes[o] = k
            darkerBytes[o + 1] = k
            darkerBytes[o + 2] = k
            darkerBytes[o + 3] = 255
        }
        let lighter: CGImage = image(fromBGRA: lighterBytes, width: width, height: height)
        let darker: CGImage = image(fromBGRA: darkerBytes, width: width, height: height)
        return (lighter: lighter, darker: darker)
    }

    /// Opaque 32-bit BGRA image (byte order B, G, R, X) from `4·W·H` bytes.
    static func image(fromBGRA bytes: [UInt8], width: Int, height: Int) -> CGImage {
        precondition(bytes.count == 4 * width * height, "WatermarkTile: byte count mismatch")
        let data: Data = Data(bytes)
        // CGDataProvider(data:) only fails for a nil CFData; `data as CFData` never is.
        let provider: CGDataProvider = CGDataProvider(data: data as CFData)!
        let bitmapInfo: CGBitmapInfo = CGBitmapInfo(
            rawValue: CGBitmapInfo.byteOrder32Little.rawValue | CGImageAlphaInfo.noneSkipFirst.rawValue)
        // All parameters are consistent (8 bpc, 32 bpp, bytesPerRow = 4·W, RGB space,
        // provider holds exactly 4·W·H bytes), so this initializer cannot fail.
        let image: CGImage = CGImage(
            width: width,
            height: height,
            bitsPerComponent: 8,
            bitsPerPixel: 32,
            bytesPerRow: 4 * width,
            space: CGColorSpaceCreateDeviceRGB(),
            bitmapInfo: bitmapInfo,
            provider: provider,
            decode: nil,
            shouldInterpolate: false,
            intent: .defaultIntent)!
        return image
    }

    /// Reads one pixel of an image produced by `image(fromBGRA:…)` back as
    /// (r, g, b) — for Diagnostics' offline self-check and the WP5 sampled-pixel test.
    static func samplePixel(_ image: CGImage, x: Int, y: Int) -> (r: UInt8, g: UInt8, b: UInt8)? {
        guard x >= 0, y >= 0, x < image.width, y < image.height,
              let provider = image.dataProvider,
              let cfData = provider.data else {
            return nil
        }
        let data: Data = cfData as Data
        let offset: Int = y * image.bytesPerRow + 4 * x
        guard offset + 3 < data.count else { return nil }
        return (r: data[offset + 2], g: data[offset + 1], b: data[offset])
    }
}
