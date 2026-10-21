import XCTest
@testable import Kilit

final class Base64urlTests: XCTestCase {
    func testVectorCases() throws {
        let root: [String: Any] = try Vec.object(KilitVectors.base64url)
        let cases: [[String: Any]] = try Vec.dicts(root, "cases")
        XCTAssertFalse(cases.isEmpty)
        for c in cases {
            let bytes: Data = try Vec.hex(c, "bytes")
            let text: String = try Vec.str(c, "text")
            XCTAssertEqual(bytes.base64url(), text)
            XCTAssertEqual(Data(base64url: text), bytes)
        }
    }

    func testVectorNegatives() throws {
        let root: [String: Any] = try Vec.object(KilitVectors.base64url)
        let negatives: [[String: Any]] = try Vec.dicts(root, "negative")
        XCTAssertEqual(negatives.count, 4)
        for n in negatives {
            let text: String = try Vec.str(n, "text")
            let caseName: String = try Vec.str(n, "name")
            XCTAssertNil(Data(base64url: text), caseName)
            XCTAssertEqual(try Vec.str(n, "error"), "bad_envelope")
        }
    }

    func testLengthMod3AndHighBytes() {
        let inputs: [Data] = [
            Data(),
            Data([0xFF]),
            Data([0xFF, 0x80]),
            Data([0xFB, 0xFF, 0xBF]),
            Data([0x00, 0x01, 0x02, 0x03]),
            Data(repeating: 0xFF, count: 32),
        ]
        for d in inputs {
            let text: String = d.base64url()
            XCTAssertFalse(text.contains("="))
            XCTAssertFalse(text.contains("+"))
            XCTAssertFalse(text.contains("/"))
            XCTAssertEqual(Data(base64url: text), d)
        }
        XCTAssertEqual(Data([0xFB, 0xFF, 0xBF]).base64url(), "-_-_")
        XCTAssertEqual(Data([0xFF]).base64url(), "_w")
        XCTAssertEqual(Data([0xFF, 0xFF]).base64url(), "__8")
    }

    func testStrictRules() {
        XCTAssertNil(Data(base64url: "AQ=="), "padding")
        XCTAssertNil(Data(base64url: "AQ+/"), "alphabet")
        XCTAssertNil(Data(base64url: "AQIDB"), "length mod 4 == 1")
        XCTAssertNil(Data(base64url: "AR"), "trailing bits")
        XCTAssertNil(Data(base64url: "AQI "), "whitespace")
        XCTAssertNil(Data(base64url: "AQI\n"), "newline")
        XCTAssertEqual(Data(base64url: "AQ"), Data([0x01]))
        XCTAssertEqual(Data(base64url: "AQI"), Data([0x01, 0x02]))
        XCTAssertEqual(Data(base64url: "AQID"), Data([0x01, 0x02, 0x03]))
        XCTAssertEqual(Data(base64url: ""), Data())
    }

    func testSidIsElevenCharacters() {
        let sid: Data = Data(repeating: 0xAB, count: 8)
        XCTAssertEqual(sid.base64url().count, 11)
        XCTAssertEqual(Data(base64url: sid.base64url()), sid)
    }

    func testHex() {
        XCTAssertEqual(Data(hex: "00ff10"), Data([0x00, 0xFF, 0x10]))
        XCTAssertEqual(Data(hex: "00FF10"), Data([0x00, 0xFF, 0x10]))
        XCTAssertNil(Data(hex: "0"))
        XCTAssertNil(Data(hex: "zz"))
        XCTAssertEqual(Data([0x00, 0xFF, 0x10]).hex, "00ff10")
        XCTAssertEqual(Data(hex: ""), Data())
    }
}
