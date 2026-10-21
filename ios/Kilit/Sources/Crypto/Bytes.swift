import Foundation
import CryptoKit

// MARK: - Hex

extension Data {
    /// Parses lowercase or uppercase hex; returns nil on odd length or a non-hex character.
    init?(hex: String) {
        let chars: [UInt8] = Array(hex.utf8)
        guard chars.count % 2 == 0 else { return nil }
        var out: [UInt8] = []
        out.reserveCapacity(chars.count / 2)
        var index: Int = 0
        while index < chars.count {
            guard let hi = Data.nibble(chars[index]), let lo = Data.nibble(chars[index + 1]) else { return nil }
            out.append(hi << 4 | lo)
            index += 2
        }
        self.init(out)
    }

    private static func nibble(_ c: UInt8) -> UInt8? {
        switch c {
        case 0x30...0x39: return c - 0x30
        case 0x61...0x66: return c - 0x61 + 10
        case 0x41...0x46: return c - 0x41 + 10
        default: return nil
        }
    }

    /// Lowercase hex.
    var hex: String {
        let digits: [UInt8] = Array("0123456789abcdef".utf8)
        var out: [UInt8] = []
        out.reserveCapacity(count * 2)
        for b in self {
            out.append(digits[Int(b >> 4)])
            out.append(digits[Int(b & 0x0F)])
        }
        return String(decoding: out, as: UTF8.self)
    }
}

// MARK: - Base64url (RFC 4648 §5, unpadded, strict decode)

enum Base64URL {
    private static let alphabet: [UInt8] = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".utf8)

    private static let reverse: [Int8] = {
        var table: [Int8] = Array(repeating: -1, count: 256)
        for (i, c) in alphabet.enumerated() {
            table[Int(c)] = Int8(i)
        }
        return table
    }()

    static func encode(_ data: Data) -> String {
        var out: [UInt8] = []
        out.reserveCapacity((data.count + 2) / 3 * 4)
        let bytes: [UInt8] = Array(data)
        var i: Int = 0
        while i + 3 <= bytes.count {
            let n: UInt32 = UInt32(bytes[i]) << 16 | UInt32(bytes[i + 1]) << 8 | UInt32(bytes[i + 2])
            out.append(alphabet[Int((n >> 18) & 63)])
            out.append(alphabet[Int((n >> 12) & 63)])
            out.append(alphabet[Int((n >> 6) & 63)])
            out.append(alphabet[Int(n & 63)])
            i += 3
        }
        let rest: Int = bytes.count - i
        if rest == 1 {
            let n: UInt32 = UInt32(bytes[i]) << 16
            out.append(alphabet[Int((n >> 18) & 63)])
            out.append(alphabet[Int((n >> 12) & 63)])
        } else if rest == 2 {
            let n: UInt32 = UInt32(bytes[i]) << 16 | UInt32(bytes[i + 1]) << 8
            out.append(alphabet[Int((n >> 18) & 63)])
            out.append(alphabet[Int((n >> 12) & 63)])
            out.append(alphabet[Int((n >> 6) & 63)])
        }
        return String(decoding: out, as: UTF8.self)
    }

    /// Strict decode: rejects `=`, any character outside the alphabet (whitespace, `+`, `/`),
    /// encoded length ≡ 1 (mod 4) and non-zero trailing bits in the last character.
    static func decode(_ text: String) -> Data? {
        let chars: [UInt8] = Array(text.utf8)
        if chars.count % 4 == 1 { return nil }
        var values: [UInt8] = []
        values.reserveCapacity(chars.count)
        for c in chars {
            let v: Int8 = reverse[Int(c)]
            if v < 0 { return nil }
            values.append(UInt8(v))
        }
        var out: [UInt8] = []
        out.reserveCapacity(chars.count * 3 / 4)
        var i: Int = 0
        while i + 4 <= values.count {
            let n: UInt32 = UInt32(values[i]) << 18 | UInt32(values[i + 1]) << 12 | UInt32(values[i + 2]) << 6 | UInt32(values[i + 3])
            out.append(UInt8((n >> 16) & 0xFF))
            out.append(UInt8((n >> 8) & 0xFF))
            out.append(UInt8(n & 0xFF))
            i += 4
        }
        let rest: Int = values.count - i
        if rest == 2 {
            // 12 bits carry one byte; the low 4 bits of the last char must be zero.
            if values[i + 1] & 0x0F != 0 { return nil }
            let n: UInt32 = UInt32(values[i]) << 18 | UInt32(values[i + 1]) << 12
            out.append(UInt8((n >> 16) & 0xFF))
        } else if rest == 3 {
            // 18 bits carry two bytes; the low 2 bits of the last char must be zero.
            if values[i + 2] & 0x03 != 0 { return nil }
            let n: UInt32 = UInt32(values[i]) << 18 | UInt32(values[i + 1]) << 12 | UInt32(values[i + 2]) << 6
            out.append(UInt8((n >> 16) & 0xFF))
            out.append(UInt8((n >> 8) & 0xFF))
        }
        return Data(out)
    }
}

extension Data {
    init?(base64url text: String) {
        guard let d = Base64URL.decode(text) else { return nil }
        self = d
    }

    func base64url() -> String {
        Base64URL.encode(self)
    }
}

// MARK: - Big-endian integers

enum BE {
    static func u16(_ v: UInt16) -> Data {
        Data([UInt8(v >> 8 & 0xFF), UInt8(v & 0xFF)])
    }

    static func u32(_ v: UInt32) -> Data {
        Data([UInt8(v >> 24 & 0xFF), UInt8(v >> 16 & 0xFF), UInt8(v >> 8 & 0xFF), UInt8(v & 0xFF)])
    }

    static func u64(_ v: UInt64) -> Data {
        var out: [UInt8] = []
        out.reserveCapacity(8)
        var shift: UInt64 = 56
        while true {
            out.append(UInt8((v >> shift) & 0xFF))
            if shift == 0 { break }
            shift -= 8
        }
        return Data(out)
    }

    /// Reads a big-endian UInt32 from `data` at absolute `offset` (caller guarantees 4 bytes are present).
    static func readU32(_ data: Data, at offset: Int) -> UInt32 {
        let b: [UInt8] = Array(data[(data.startIndex + offset)..<(data.startIndex + offset + 4)])
        return UInt32(b[0]) << 24 | UInt32(b[1]) << 16 | UInt32(b[2]) << 8 | UInt32(b[3])
    }
}

// MARK: - Byte helpers

enum Bytes {
    /// Constant-time "all zero" check (OR-accumulate over every byte).
    static func isAllZero(_ data: Data) -> Bool {
        var acc: UInt8 = 0
        for b in data { acc |= b }
        return acc == 0
    }

    /// Lexicographic (unsigned bytewise) comparison: true when `a < b`.
    static func lexLess(_ a: Data, _ b: Data) -> Bool {
        let n: Int = Swift.min(a.count, b.count)
        var i: Int = 0
        while i < n {
            let x: UInt8 = a[a.startIndex + i]
            let y: UInt8 = b[b.startIndex + i]
            if x != y { return x < y }
            i += 1
        }
        return a.count < b.count
    }

    /// A fresh `Data` with its own storage (startIndex 0), so slicing never leaks indices.
    static func copy(_ data: Data) -> Data {
        Data(Array(data))
    }

    static func utf8(_ s: String) -> Data {
        Data(s.utf8)
    }

    /// Cryptographically secure random bytes.
    static func random(_ count: Int) -> Data {
        // SymmetricKey draws from the system CSPRNG and is zeroised on deallocation.
        let key: SymmetricKey = SymmetricKey(size: SymmetricKeySize(bitCount: Swift.max(8, count * 8)))
        let d: Data = key.withUnsafeBytes { Data($0) }
        return d.prefix(count)
    }
}

// MARK: - ZeroizingKey

/// Private-key material held in `SymmetricKey`-backed storage, which CryptoKit zeroises on deallocation.
/// Codable as the raw bytes (base64 string, Foundation's default `Data` coding), so the sealed store
/// documents of WP7 can hold it; the transient `Data` copies made for coding or DH are unavoidable.
struct ZeroizingKey: Equatable, Codable {
    private let key: SymmetricKey

    init(data: Data) {
        self.key = SymmetricKey(data: data)
    }

    var count: Int {
        key.bitCount / 8
    }

    func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try key.withUnsafeBytes(body)
    }

    /// A plain copy of the bytes (not zeroised); use only for a DH or a store write.
    var dataCopy: Data {
        key.withUnsafeBytes { Data($0) }
    }

    func x25519PrivateKey() throws -> Curve25519.KeyAgreement.PrivateKey {
        try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: key)
    }

    static func == (lhs: ZeroizingKey, rhs: ZeroizingKey) -> Bool {
        lhs.key == rhs.key
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let d: Data = try container.decode(Data.self)
        self.key = SymmetricKey(data: d)
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(dataCopy)
    }
}
