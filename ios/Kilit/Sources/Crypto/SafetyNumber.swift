import Foundation
import CryptoKit

/// Safety number (§3.6): per party 5200 SHA-256 rounds → 30 digits; 60 digits, smaller 30-digit string first.
enum SafetyNumber {
    static let iterations: Int = 5199

    struct Party: Equatable {
        let username: String
        let ikSig: Data
        let ikDh: Data

        init(username: String, ikSig: Data, ikDh: Data) {
            self.username = username
            self.ikSig = ikSig
            self.ikDh = ikDh
        }

        init(username: String, identity: IdentityPublicKeys) {
            self.username = username
            self.ikSig = identity.ikSig
            self.ikDh = identity.ikDh
        }
    }

    /// `h = SHA256("Kilit_SafetyNumber_v1" || IK_sig || IK_dh || username)`, then 5199 × `h = SHA256(h || IK_sig || IK_dh)`;
    /// `h[0:30]` as six 5-byte big-endian integers mod 100000, zero-padded to 5 digits.
    static func digits(username: String, ikSig: Data, ikDh: Data) -> String {
        var seed: Data = Data(KilitInfo.safetyNumber.utf8)
        seed.append(ikSig)
        seed.append(ikDh)
        seed.append(Data(username.utf8))
        var h: Data = KDF.sha256(seed)
        var i: Int = 0
        while i < iterations {
            var buf: Data = h
            buf.append(ikSig)
            buf.append(ikDh)
            h = KDF.sha256(buf)
            i += 1
        }
        let bytes: [UInt8] = Array(h)
        var out: String = ""
        var chunk: Int = 0
        while chunk < 6 {
            let base: Int = chunk * 5
            var v: UInt64 = 0
            var j: Int = 0
            while j < 5 {
                v = v << 8 | UInt64(bytes[base + j])
                j += 1
            }
            let group: UInt64 = v % 100000
            let s: String = String(group)
            out += String(repeating: "0", count: 5 - s.count) + s
            chunk += 1
        }
        return out
    }

    static func digits(_ party: Party) -> String {
        digits(username: party.username, ikSig: party.ikSig, ikDh: party.ikDh)
    }

    /// 60 digits: lexicographically smaller 30-digit string first.
    static func number(_ a: Party, _ b: Party) -> String {
        let da: String = digits(a)
        let db: String = digits(b)
        return da < db ? da + db : db + da
    }

    static func qrString(_ number: String) -> String {
        KilitInfo.safetyQRPrefix + number
    }

    /// 12 groups of 5 digits separated by spaces.
    static func grouped(_ number: String) -> String {
        let chars: [Character] = Array(number)
        var groups: [String] = []
        var i: Int = 0
        while i < chars.count {
            let end: Int = Swift.min(i + 5, chars.count)
            groups.append(String(chars[i..<end]))
            i += 5
        }
        return groups.joined(separator: " ")
    }
}
