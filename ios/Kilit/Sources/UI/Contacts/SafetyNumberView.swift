//  SafetyNumberView.swift
//  Kilit — UI/Contacts (WP8), §3.6.
//
//  60-digit safety number in 12 groups of 5, a QR of `kilit-sn:v1:<digits>`
//  (minimal byte-mode QR encoder below: version 5, level L, mask 0 — no
//  CoreImage dependency) and the "Doğrulandı" toggle. The keys are the contact
//  record's identity keys (the decrypt path asserts they equal the session AD).

import SwiftUI

struct SafetyNumberView: View {
    let peer: String

    @Environment(AppModel.self) private var model: AppModel
    @Environment(\.dismiss) private var dismiss: DismissAction

    private var contact: ContactRecord? { model.contacts.first { $0.username == peer } }

    private var number: String? {
        guard let mine = model.localPublicKeys, let theirs = contact?.identity else { return nil }
        let a: SafetyNumber.Party = SafetyNumber.Party(username: model.username, identity: mine)
        let b: SafetyNumber.Party = SafetyNumber.Party(username: peer, identity: theirs)
        return SafetyNumber.number(a, b)
    }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 20) {
                    if let number {
                        QRCodeView(text: SafetyNumber.qrString(number))
                            .frame(width: 220, height: 220)
                            .padding(12)
                            .background(Color.white, in: RoundedRectangle(cornerRadius: 12))
                        Text(SafetyNumber.grouped(number))
                            .font(.system(.body, design: .monospaced))
                            .multilineTextAlignment(.center)
                            .padding(.horizontal)
                        Text(String(localized: "safety.explain",
                                    defaultValue: "Bu numarayı \(peer) ile başka bir kanaldan karşılaştır. Aynıysa aradaki bağlantıya kimse araya girmemiştir."))
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                            .multilineTextAlignment(.center)
                            .padding(.horizontal)
                        Toggle(isOn: Binding(
                            get: { contact?.verified ?? false },
                            set: { on in Task { await model.setVerified(peer: peer, verified: on) } })) {
                            Label(String(localized: "safety.verified", defaultValue: "Doğrulandı"),
                                  systemImage: "checkmark.seal")
                        }
                        .padding(.horizontal)
                    } else {
                        Text(String(localized: "safety.unavailable", defaultValue: "Güvenlik numarası henüz hesaplanamıyor"))
                            .foregroundStyle(.secondary)
                    }
                }
                .padding(.vertical, 24)
            }
            .navigationTitle(String(localized: "safety.title", defaultValue: "Güvenlik numarası"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button(String(localized: "common.ok", defaultValue: "Tamam")) { dismiss() }
                }
            }
        }
    }
}

/// Draws the module matrix with SwiftUI `Canvas` (no CoreImage).
struct QRCodeView: View {
    let text: String

    var body: some View {
        if let modules = QRCode.modules(for: text) {
            Canvas { context, size in
                let n: Int = modules.count
                let cell: CGFloat = min(size.width, size.height) / CGFloat(n)
                for y in 0..<n {
                    for x in 0..<n where modules[y][x] {
                        let rect: CGRect = CGRect(x: CGFloat(x) * cell, y: CGFloat(y) * cell, width: cell, height: cell)
                        context.fill(Path(rect), with: .color(.black))
                    }
                }
            }
            .accessibilityHidden(true)
        } else {
            Text(text).font(.caption2)
        }
    }
}

/// Minimal QR encoder: version 5 (37×37), error correction L (108 data + 26 EC
/// codewords, one block), byte mode, mask pattern 0. Enough for the 72-byte
/// safety string; returns nil above 106 bytes.
enum QRCode {
    static let version: Int = 5
    static let size: Int = 37
    static let dataCodewords: Int = 108
    static let ecCodewords: Int = 26
    static let alignmentCenters: [Int] = [6, 30]

    static func modules(for text: String) -> [[Bool]]? {
        let bytes: [UInt8] = Array(text.utf8)
        guard bytes.count <= dataCodewords - 2 else { return nil }
        let codewords: [UInt8] = encodeData(bytes) + reedSolomonRemainder(encodeData(bytes), divisor: divisor(ecCodewords))
        var grid: [[Bool]] = Array(repeating: Array(repeating: false, count: size), count: size)
        var function: [[Bool]] = grid
        drawFunctionPatterns(&grid, &function)
        drawCodewords(codewords, &grid, function)
        applyMask(&grid, function)
        drawFormatBits(&grid, &function)
        return grid
    }

    // MARK: data segment

    static func encodeData(_ bytes: [UInt8]) -> [UInt8] {
        var bits: [Bool] = []
        func append(_ value: Int, _ count: Int) {
            var i: Int = count - 1
            while i >= 0 {
                bits.append((value >> i) & 1 == 1)
                i -= 1
            }
        }
        append(0b0100, 4)
        append(bytes.count, 8)
        for b in bytes { append(Int(b), 8) }
        let capacity: Int = dataCodewords * 8
        append(0, min(4, capacity - bits.count))
        while bits.count % 8 != 0 { bits.append(false) }
        var out: [UInt8] = []
        var i: Int = 0
        while i < bits.count {
            var byte: UInt8 = 0
            for j in 0..<8 where bits[i + j] { byte |= UInt8(1 << (7 - j)) }
            out.append(byte)
            i += 8
        }
        var pad: UInt8 = 0xEC
        while out.count < dataCodewords {
            out.append(pad)
            pad = pad == 0xEC ? 0x11 : 0xEC
        }
        return out
    }

    // MARK: Reed–Solomon over GF(256), polynomial 0x11D

    static func multiply(_ x: UInt8, _ y: UInt8) -> UInt8 {
        var z: Int = 0
        var i: Int = 7
        while i >= 0 {
            z = (z << 1) ^ ((z >> 7) * 0x11D)
            z ^= ((Int(y) >> i) & 1) * Int(x)
            i -= 1
        }
        return UInt8(z & 0xFF)
    }

    static func divisor(_ degree: Int) -> [UInt8] {
        var result: [UInt8] = Array(repeating: 0, count: degree)
        result[degree - 1] = 1
        var root: UInt8 = 1
        for _ in 0..<degree {
            for j in 0..<degree {
                result[j] = multiply(result[j], root)
                if j + 1 < degree { result[j] ^= result[j + 1] }
            }
            root = multiply(root, 0x02)
        }
        return result
    }

    static func reedSolomonRemainder(_ data: [UInt8], divisor: [UInt8]) -> [UInt8] {
        var result: [UInt8] = Array(repeating: 0, count: divisor.count)
        for b in data {
            let factor: UInt8 = b ^ result.removeFirst()
            result.append(0)
            for i in 0..<divisor.count {
                result[i] ^= multiply(divisor[i], factor)
            }
        }
        return result
    }

    // MARK: function patterns

    static func set(_ grid: inout [[Bool]], _ function: inout [[Bool]], x: Int, y: Int, _ dark: Bool) {
        grid[y][x] = dark
        function[y][x] = true
    }

    static func drawFunctionPatterns(_ grid: inout [[Bool]], _ function: inout [[Bool]]) {
        for i in 0..<size {
            set(&grid, &function, x: 6, y: i, i % 2 == 0)
            set(&grid, &function, x: i, y: 6, i % 2 == 0)
        }
        drawFinder(&grid, &function, cx: 3, cy: 3)
        drawFinder(&grid, &function, cx: size - 4, cy: 3)
        drawFinder(&grid, &function, cx: 3, cy: size - 4)
        let n: Int = alignmentCenters.count
        for i in 0..<n {
            for j in 0..<n {
                let skip: Bool = (i == 0 && j == 0) || (i == 0 && j == n - 1) || (i == n - 1 && j == 0)
                if !skip { drawAlignment(&grid, &function, cx: alignmentCenters[i], cy: alignmentCenters[j]) }
            }
        }
        drawFormatBits(&grid, &function)          // reserves the areas; redrawn after masking
    }

    static func drawFinder(_ grid: inout [[Bool]], _ function: inout [[Bool]], cx: Int, cy: Int) {
        for dy in -4...4 {
            for dx in -4...4 {
                let x: Int = cx + dx
                let y: Int = cy + dy
                guard x >= 0, y >= 0, x < size, y < size else { continue }
                let dist: Int = max(abs(dx), abs(dy))
                set(&grid, &function, x: x, y: y, dist != 2 && dist != 4)
            }
        }
    }

    static func drawAlignment(_ grid: inout [[Bool]], _ function: inout [[Bool]], cx: Int, cy: Int) {
        for dy in -2...2 {
            for dx in -2...2 {
                set(&grid, &function, x: cx + dx, y: cy + dy, max(abs(dx), abs(dy)) != 1)
            }
        }
    }

    /// BCH(15,5) format information for level L (01) and mask 0, both copies.
    static func drawFormatBits(_ grid: inout [[Bool]], _ function: inout [[Bool]]) {
        let data: Int = (1 << 3) | 0                 // L = 01, mask 0
        var rem: Int = data
        for _ in 0..<10 {
            rem = (rem << 1) ^ ((rem >> 9) * 0x537)
        }
        let bits: Int = ((data << 10) | rem) ^ 0x5412
        func bit(_ i: Int) -> Bool { (bits >> i) & 1 == 1 }
        for i in 0..<6 { set(&grid, &function, x: 8, y: i, bit(i)) }
        set(&grid, &function, x: 8, y: 7, bit(6))
        set(&grid, &function, x: 8, y: 8, bit(7))
        set(&grid, &function, x: 7, y: 8, bit(8))
        for i in 9..<15 { set(&grid, &function, x: 14 - i, y: 8, bit(i)) }
        for i in 0..<8 { set(&grid, &function, x: size - 1 - i, y: 8, bit(i)) }
        for i in 8..<15 { set(&grid, &function, x: 8, y: size - 15 + i, bit(i)) }
        set(&grid, &function, x: 8, y: size - 8, true)
    }

    // MARK: codeword placement and mask

    static func drawCodewords(_ data: [UInt8], _ grid: inout [[Bool]], _ function: [[Bool]]) {
        var i: Int = 0
        let total: Int = data.count * 8
        var right: Int = size - 1
        while right >= 1 {
            if right == 6 { right = 5 }                  // skip the timing column for good
            for vert in 0..<size {
                for j in 0..<2 {
                    let x: Int = right - j
                    let upward: Bool = ((right + 1) & 2) == 0
                    let y: Int = upward ? size - 1 - vert : vert
                    if !function[y][x] && i < total {
                        grid[y][x] = (data[i >> 3] >> (7 - (i & 7))) & 1 == 1
                        i += 1
                    }
                }
            }
            right -= 2
        }
    }

    static func applyMask(_ grid: inout [[Bool]], _ function: [[Bool]]) {
        for y in 0..<size {
            for x in 0..<size where !function[y][x] && (x + y) % 2 == 0 {
                grid[y][x].toggle()
            }
        }
    }
}
