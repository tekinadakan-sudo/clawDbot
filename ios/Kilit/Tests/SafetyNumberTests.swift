import XCTest
@testable import Kilit

final class SafetyNumberTests: XCTestCase {
    private var root: [String: Any] = [:]

    override func setUpWithError() throws {
        root = try Vec.object(KilitVectors.safety)
    }

    private func party(named name: String) throws -> SafetyNumber.Party {
        for c in try Vec.dicts(root, "cases") {
            let username: String = try Vec.str(c, "username")
            if username == name {
                return SafetyNumber.Party(username: name, ikSig: try Vec.hex(c, "ik_sig"), ikDh: try Vec.hex(c, "ik_dh"))
            }
        }
        throw VecError("no case for \(name)")
    }

    func testPerPartyDigits() throws {
        let cases: [[String: Any]] = try Vec.dicts(root, "cases")
        XCTAssertFalse(cases.isEmpty)
        for c in cases {
            let digits: String = SafetyNumber.digits(username: try Vec.str(c, "username"),
                                                     ikSig: try Vec.hex(c, "ik_sig"), ikDh: try Vec.hex(c, "ik_dh"))
            XCTAssertEqual(digits, try Vec.str(c, "digits"))
            XCTAssertEqual(digits.count, 30)
            XCTAssertTrue(digits.allSatisfy { $0.isNumber })
        }
    }

    func testPairs() throws {
        for p in try Vec.dicts(root, "pairs") {
            let a: SafetyNumber.Party = try party(named: try Vec.str(p, "a"))
            let b: SafetyNumber.Party = try party(named: try Vec.str(p, "b"))
            let number: String = SafetyNumber.number(a, b)
            XCTAssertEqual(number, try Vec.str(p, "number"))
            XCTAssertEqual(SafetyNumber.number(b, a), number, "symmetric")
            XCTAssertEqual(number.count, 60)
            XCTAssertEqual(SafetyNumber.qrString(number), try Vec.str(p, "qr"))
            let grouped: String = SafetyNumber.grouped(number)
            XCTAssertEqual(grouped.split(separator: " ").count, 12)
            XCTAssertEqual(grouped.replacingOccurrences(of: " ", with: ""), number)
        }
    }

    func testSmallerStringFirstAndSensitivity() {
        let a: SafetyNumber.Party = SafetyNumber.Party(username: "alice", ikSig: Data(repeating: 1, count: 32), ikDh: Data(repeating: 2, count: 32))
        let b: SafetyNumber.Party = SafetyNumber.Party(username: "bob", ikSig: Data(repeating: 3, count: 32), ikDh: Data(repeating: 4, count: 32))
        let da: String = SafetyNumber.digits(a)
        let db: String = SafetyNumber.digits(b)
        let n: String = SafetyNumber.number(a, b)
        XCTAssertEqual(n, da < db ? da + db : db + da)
        // Any key or username change changes the digits.
        let a2: SafetyNumber.Party = SafetyNumber.Party(username: "alicf", ikSig: a.ikSig, ikDh: a.ikDh)
        XCTAssertNotEqual(SafetyNumber.digits(a2), da)
        var sig: Data = a.ikSig
        sig[sig.startIndex] ^= 1
        XCTAssertNotEqual(SafetyNumber.digits(SafetyNumber.Party(username: "alice", ikSig: sig, ikDh: a.ikDh)), da)
        // Party from an identity record.
        let rec: IdentityPublicKeys = IdentityPublicKeys(ikSig: a.ikSig, ikDh: a.ikDh)
        XCTAssertEqual(SafetyNumber.digits(SafetyNumber.Party(username: "alice", identity: rec)), da)
    }
}
