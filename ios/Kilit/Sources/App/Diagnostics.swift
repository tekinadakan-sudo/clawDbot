//  Diagnostics.swift
//  Kilit — App/ (WP8), §5.1 / §5.9.
//
//  Diagnostics state shown in Settings › Tanılama: secure-canvas availability
//  and mode, panel Hz, measured flicker Hz, capture state, OPK count, the
//  undecryptable log, the capture log and every `wm_secret` in hex (smallest
//  `sid` first, for `wmdecode -ws`). Also the WP8-owned watermark wiring:
//  `WatermarkPayload.deltaMap(scale:)` → `WatermarkTile.make` cached per
//  (payload, displayScale), and the offline tile self-check (§5.9 reviewer note).

import CoreGraphics
import Foundation
import Observation

// MARK: - Watermark tile cache (payload → tile, per display scale)

final class WatermarkTileCache {

    struct Key: Hashable {
        let payload16: UInt16
        let scale: Int
    }

    private var tiles: [Key: (lighter: CGImage, darker: CGImage)] = [:]

    init() {}

    /// Integer scale for a display scale (1, 2 or 3).
    static func integerScale(_ displayScale: CGFloat) -> Int {
        min(3, max(1, Int(displayScale.rounded())))
    }

    func tiles(for payload: WatermarkPayload, displayScale: CGFloat) -> (lighter: CGImage, darker: CGImage) {
        let scale: Int = WatermarkTileCache.integerScale(displayScale)
        let key: Key = Key(payload16: payload.payload16, scale: scale)
        if let cached = tiles[key] { return cached }
        let side: Int = WatermarkPayload.size(scale: scale)
        let delta: [Int8] = payload.deltaMap(scale: scale)
        let made: (lighter: CGImage, darker: CGImage) = WatermarkTile.make(
            delta: delta, width: side, height: side, scale: CGFloat(scale))
        tiles[key] = made
        return made
    }

    func removeAll() {
        tiles.removeAll()
    }
}

// MARK: - Diagnostics

@MainActor
@Observable
final class Diagnostics {

    var secureCanvasAvailable: Bool = false
    var secureLayerMode: SecureLayerMode = .canvas
    var secureLayerEnabled: Bool = true
    var panelHz: Int = 0
    var measuredHz: Double = 0
    var flickerStopReason: String? = nil
    var isCaptured: Bool = false
    var opkCount: Int? = nil
    var undecryptableLog: [UndecryptableEntry] = []
    var captureLog: [CaptureEvent] = []
    /// `wm_secrets` per contact, smallest `sid` first: (peer, sid hex, ws hex).
    var wmSecrets: [WMSecretRow] = []
    /// Wire spellings of `ctrl.capture.kind` that `CaptureEventKind(rawValue:)` rejected.
    var unknownCaptureKinds: [String] = []
    var tileSelfCheckPassed: Bool? = nil
    var connection: WSState = .stopped

    struct WMSecretRow: Identifiable, Equatable {
        let peer: String
        let sidHex: String
        let wsHex: String
        var id: String { peer + ":" + sidHex }
    }

    init() {}

    func noteUnknownCaptureKind(_ kind: String) {
        if !unknownCaptureKinds.contains(kind) {
            unknownCaptureKinds.append(kind)
        }
    }

    /// Reads everything derivable from the store index.
    func apply(index: StoreIndex) {
        undecryptableLog = Array(index.undecryptableLog.suffix(100)).reversed()
        captureLog = Array(index.captureLog.suffix(100)).reversed()
        var rows: [WMSecretRow] = []
        for contact in index.contacts {
            let sorted: [WMSecret] = contact.wmSecrets.sorted { Bytes.lexLess($0.sid, $1.sid) }
            for secret in sorted {
                rows.append(WMSecretRow(peer: contact.username, sidHex: secret.sid.hex, wsHex: secret.ws.hex))
            }
        }
        wmSecrets = rows
        secureLayerMode = SecureLayerMode(rawValue: index.settings.secureLayerMode) ?? .canvas
        secureLayerEnabled = index.settings.secureLayer
    }

    /// Offline self-check (§5.9 reviewer note): composites the two scale-1 tiles
    /// over a `#4A4A4F` field and verifies the expected ±Δ at sampled pixels.
    static func tileSelfCheck(cache: WatermarkTileCache) -> Bool {
        let payload: WatermarkPayload = WatermarkPayload(tag: 171, day: 7)
        let tiles: (lighter: CGImage, darker: CGImage) = cache.tiles(for: payload, displayScale: 1)
        let side: Int = WatermarkPayload.size(scale: 1)
        let delta: [Int8] = payload.deltaMap(scale: 1)
        guard delta.count == side * side else { return false }
        let info: UInt32 = CGImageAlphaInfo.premultipliedLast.rawValue
        guard let ctx = CGContext(data: nil, width: side, height: side, bitsPerComponent: 8, bytesPerRow: 0,
                                  space: CGColorSpaceCreateDeviceRGB(), bitmapInfo: info) else { return false }
        let rect: CGRect = CGRect(x: 0, y: 0, width: side, height: side)
        let field: CGFloat = 0x4A / 255.0
        ctx.setFillColor(red: field, green: field, blue: field, alpha: 1)
        ctx.fill(rect)
        ctx.setBlendMode(.plusLighter)
        ctx.draw(tiles.lighter, in: rect)
        ctx.setBlendMode(.plusDarker)
        ctx.draw(tiles.darker, in: rect)
        guard let base = ctx.data else { return false }
        let bytesPerRow: Int = ctx.bytesPerRow
        let samples: [(x: Int, y: Int)] = [(0, 0), (7, 3), (20, 20), (41, 13), (100, 77), (167, 167), (84, 0), (0, 150)]
        for s in samples {
            // Core Graphics draws bottom-up: context row r holds image row side − 1 − r.
            let contextRow: Int = side - 1 - s.y
            let offset: Int = contextRow * bytesPerRow + 4 * s.x
            let red: Int = Int(base.load(fromByteOffset: offset, as: UInt8.self))
            let expected: Int = 0x4A + Int(delta[s.y * side + s.x])
            if abs(red - expected) > 1 { return false }
        }
        return true
    }
}
