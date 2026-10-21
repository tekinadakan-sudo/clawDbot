import Foundation
import CryptoKit

/// Forensic watermark payload (§5.9): `tag(8) || day(4) || crc4(4)` laid out on a 6×6 cell tile, and the
/// integer delta map shared byte-for-byte with the Go generator. No Core Graphics here.
struct WatermarkPayload: Equatable {
    static let cellPoints: Int = 28
    static let tileCells: Int = 6
    static let amplitude: Int = 5
    static let boxWidthPerScale: Int = 4
    /// `0b10110100011100101001`, MSB first.
    static let syncBits: [Bool] = {
        let v: UInt32 = 0b1011_0100_0111_0010_1001
        var out: [Bool] = []
        var i: Int = 19
        while i >= 0 {
            out.append((v >> UInt32(i)) & 1 == 1)
            i -= 1
        }
        return out
    }()

    struct CRCStep: Equatable {
        let bit: UInt8
        let fb: UInt8
        let crc: UInt8
    }

    let tag: UInt8
    let day: UInt8
    let crc: UInt8
    let payload16: UInt16
    /// 6×6, `cells[row][col]`.
    let cells: [[Bool]]

    /// `tag = HKDF(ikm = WS, salt = zeros, info = "Kilit_WM_v1" || viewer, L = 1)[0]`, `day = (unix / 86400) mod 16`.
    init(ws: Data, viewer: String, unix: UInt64) {
        var info: Data = Data(KilitInfo.watermark.utf8)
        info.append(Data(viewer.utf8))
        let t: Data = KDF.hkdf(ikm: ws, salt: KDF.zeros32, info: info, length: 1)
        let tag: UInt8 = t[t.startIndex]
        let day: UInt8 = UInt8((unix / 86400) % 16)
        self.init(tag: tag, day: day)
    }

    init(tag: UInt8, day: UInt8) {
        self.tag = tag
        self.day = day & 0x0F
        self.crc = WatermarkPayload.crc4(tag: tag, day: day & 0x0F)
        self.payload16 = UInt16(tag) << 8 | UInt16(day & 0x0F) << 4 | UInt16(self.crc)
        self.cells = WatermarkPayload.layout(payload16: self.payload16)
    }

    // MARK: CRC-4 (x⁴ + x + 1, MSB-first, init 0, no final XOR)

    static func crc4Steps(tag: UInt8, day: UInt8) -> [CRCStep] {
        var bits: [UInt8] = []
        var i: Int = 7
        while i >= 0 {
            bits.append((tag >> UInt8(i)) & 1)
            i -= 1
        }
        i = 3
        while i >= 0 {
            bits.append((day >> UInt8(i)) & 1)
            i -= 1
        }
        var crc: UInt8 = 0
        var steps: [CRCStep] = []
        for bit in bits {
            let fb: UInt8 = ((crc >> 3) & 1) ^ bit
            crc = ((crc << 1) & 0xF) ^ (fb == 1 ? 0x3 : 0)
            steps.append(CRCStep(bit: bit, fb: fb, crc: crc))
        }
        return steps
    }

    static func crc4(tag: UInt8, day: UInt8) -> UInt8 {
        crc4Steps(tag: tag, day: day).last?.crc ?? 0
    }

    // MARK: Layout

    /// Border cells in order: top row L→R, right column downwards, bottom row R→L, left column upwards.
    static let borderOrder: [(row: Int, col: Int)] = {
        var out: [(row: Int, col: Int)] = []
        for c in 0..<6 { out.append((0, c)) }
        for r in 1..<6 { out.append((r, 5)) }
        var c: Int = 4
        while c >= 0 { out.append((5, c)); c -= 1 }
        var r: Int = 4
        while r >= 1 { out.append((r, 0)); r -= 1 }
        return out
    }()

    /// Sync on the 20 border cells; payload bits 15…0 row-major on the inner 4×4 (bit 15 in `(1,1)`).
    static func layout(payload16: UInt16) -> [[Bool]] {
        var cells: [[Bool]] = Array(repeating: Array(repeating: false, count: tileCells), count: tileCells)
        for (i, pos) in borderOrder.enumerated() {
            cells[pos.row][pos.col] = syncBits[i]
        }
        var k: Int = 0
        while k < 16 {
            let bit: Bool = (payload16 >> UInt16(15 - k)) & 1 == 1
            cells[1 + k / 4][1 + k % 4] = bit
            k += 1
        }
        return cells
    }

    // MARK: Integer delta map

    /// `W = H = 168·s`, row-major `int8` in `[−5, 5]`: ±5 base pattern (bit 1 = left half brighter), then a
    /// separable `k = 4·s` box filter with periodic wrap using the double-mod index, and truncating division.
    func deltaMap(scale: Int) -> [Int8] {
        let s: Int = Swift.max(1, scale)
        let w: Int = WatermarkPayload.cellPoints * WatermarkPayload.tileCells * s
        let h: Int = w
        let cell: Int = WatermarkPayload.cellPoints * s
        let half: Int = cell / 2
        let k: Int = WatermarkPayload.boxWidthPerScale * s
        let amp: Int = WatermarkPayload.amplitude
        var p: [Int] = Array(repeating: 0, count: w * h)
        for y in 0..<h {
            let r: Int = y / cell
            for x in 0..<w {
                let c: Int = x / cell
                let b: Bool = cells[r][c]
                let left: Bool = (x % cell) < half
                p[y * w + x] = (b == left) ? amp : -amp
            }
        }
        var hs: [Int] = Array(repeating: 0, count: w * h)
        for y in 0..<h {
            for x in 0..<w {
                var sum: Int = 0
                var i: Int = -(k / 2)
                while i < k / 2 {
                    let xi: Int = ((x + i) % w + w) % w
                    sum += p[y * w + xi]
                    i += 1
                }
                hs[y * w + x] = sum
            }
        }
        var out: [Int8] = Array(repeating: 0, count: w * h)
        for y in 0..<h {
            for x in 0..<w {
                var sum: Int = 0
                var j: Int = -(k / 2)
                while j < k / 2 {
                    let yj: Int = ((y + j) % h + h) % h
                    sum += hs[yj * w + x]
                    j += 1
                }
                out[y * w + x] = Int8(truncatingIfNeeded: sum / (k * k))
            }
        }
        return out
    }

    /// Width/height of the map for a scale.
    static func size(scale: Int) -> Int {
        cellPoints * tileCells * Swift.max(1, scale)
    }

    /// Lighter image byte: `max(0, Δ)` in every colour channel (alpha 255).
    static func lighterByte(_ delta: Int8) -> UInt8 {
        delta > 0 ? UInt8(delta) : 0
    }

    /// Darker image byte: `255 − max(0, −Δ)`.
    static func darkerByte(_ delta: Int8) -> UInt8 {
        delta < 0 ? UInt8(255 + Int(delta)) : 255
    }
}
