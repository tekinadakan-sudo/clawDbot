import XCTest
@testable import Kilit

final class EnvelopeTests: XCTestCase {
    private var root: [String: Any] = [:]

    override func setUpWithError() throws {
        root = try Vec.object(KilitVectors.envelope)
    }

    // MARK: padding

    func testPaddingVectors() throws {
        for p in try Vec.dicts(root, "padding") {
            let json: Data = try Vec.hex(p, "json")
            let padded: Data = try Vec.hex(p, "padded")
            XCTAssertEqual(try Padding.pad(json), padded)
            XCTAssertEqual(try Padding.unpad(padded), json)
            XCTAssertEqual(padded.count % 256, 0)
            XCTAssertGreaterThan(padded.count, json.count)
        }
    }

    func testPaddingNegatives() throws {
        for p in try Vec.dicts(root, "padding_negative") {
            let padded: Data = try Vec.hex(p, "padded")
            let err: String? = Vec.errorName { _ = try Padding.unpad(padded) }
            XCTAssertEqual(err, try Vec.str(p, "error"))
        }
        // Local cases: empty, all zero, missing 0x80, len % 256 != 0.
        XCTAssertThrowsError(try Padding.unpad(Data()))
        XCTAssertThrowsError(try Padding.unpad(Data(repeating: 0, count: 256)))
        var missing: Data = Data(repeating: 0, count: 256)
        missing[missing.startIndex] = 0x41
        XCTAssertThrowsError(try Padding.unpad(missing))
        // 255 zero bytes + 0x80 is valid padding of a 255-byte all-zero payload.
        XCTAssertEqual(try Padding.unpad(Data(repeating: 0, count: 255) + Data([0x80])), Data(repeating: 0, count: 255))
        var notMultiple: Data = Data(repeating: 0, count: 300)
        notMultiple[notMultiple.startIndex] = 0x80
        XCTAssertThrowsError(try Padding.unpad(notMultiple)) { e in
            XCTAssertEqual(KilitErrorName.of(e), "badPadding")
        }
        // Boundary: 255 bytes pad to 256, 256 bytes pad to 512.
        XCTAssertEqual(try Padding.pad(Data(repeating: 1, count: 255)).count, 256)
        XCTAssertEqual(try Padding.pad(Data(repeating: 1, count: 256)).count, 512)
        XCTAssertEqual(try Padding.pad(Data()).count, 256)
    }

    func testSizeLimit() throws {
        let size: [String: Any] = try Vec.dict(root, "size")
        let okLen: Int = try Vec.int(size, "max_ok_len")
        let rejectLen: Int = try Vec.int(size, "reject_len")
        XCTAssertEqual(okLen, Padding.maxInner)
        XCTAssertNoThrow(try Padding.pad(Data(repeating: 0x20, count: okLen)))
        let err: String? = Vec.errorName { _ = try Padding.pad(Data(repeating: 0x20, count: rejectLen)) }
        XCTAssertEqual(err, try Vec.str(size, "error"))
        // The same limit applies to the encoded inner message.
        let big: InnerMessage = InnerMessage.text(id: "x", ts: 1, ttl: 0, text: String(repeating: "a", count: rejectLen))
        XCTAssertThrowsError(try big.encodedForPadding()) { e in
            XCTAssertEqual(KilitErrorName.of(e), "sizeLimit")
        }
        XCTAssertEqual(try Padding.pad(Data(repeating: 0x20, count: okLen)).count, 41216)
    }

    // MARK: outer envelope

    func testOuterVectors() throws {
        for o in try Vec.dicts(root, "outer") {
            let name: String = try Vec.str(o, "name")
            let json: String = try Vec.str(o, "json")
            let parses: Bool = Vec.bool(o, "parses")
            let err: String? = Vec.errorName { _ = try EnvelopeParser.parse(Data(json.utf8)) }
            if parses {
                XCTAssertNil(err, name)
            } else {
                XCTAssertNotNil(err, name)
                if let reason = Vec.optStr(o, "reason") {
                    // Every step-1 failure is classified bad_envelope (badHeader included).
                    XCTAssertTrue(err == reason || err == "badHeader", "\(name): \(err ?? "nil")")
                }
            }
        }
    }

    private func sampleOuter(kind: EnvelopeKind, opkId: UInt32?) throws -> OuterEnvelope {
        let hdr: Data = MessageHeader(dhPub: Data(repeating: 7, count: 32), pn: 3, n: 4).bytes
        var x3dh: X3DHBlock? = nil
        if kind == .prekey {
            x3dh = X3DHBlock(ikSig: Data(repeating: 1, count: 32), ikDh: Data(repeating: 2, count: 32),
                             ikBindSig: Data(repeating: 3, count: 64), ek: Data(repeating: 4, count: 32), spkId: 7, opkId: opkId)
        }
        let sid: Data = kind == .prekey ? X3DH.sid(ek: Data(repeating: 4, count: 32)) : Data(repeating: 9, count: 8)
        return OuterEnvelope(kind: kind, sid: sid, x3dh: x3dh, hdr: hdr, ct: Data(repeating: 0xCC, count: 272))
    }

    func testAbsentEqualsNullAndSortedKeys() throws {
        let withNull: String = #"{"ct":"\#(Data(repeating: 0xCC, count: 272).base64url())","hdr":"\#(MessageHeader(dhPub: Data(repeating: 7, count: 32), pn: 0, n: 0).bytes.base64url())","kind":"msg","sid":"\#(Data(repeating: 9, count: 8).base64url())","v":1,"x3dh":null}"#
        let withoutKey: String = #"{"ct":"\#(Data(repeating: 0xCC, count: 272).base64url())","hdr":"\#(MessageHeader(dhPub: Data(repeating: 7, count: 32), pn: 0, n: 0).bytes.base64url())","kind":"msg","sid":"\#(Data(repeating: 9, count: 8).base64url())","v":1}"#
        let a: ParsedEnvelope = try EnvelopeParser.parse(Data(withNull.utf8))
        let b: ParsedEnvelope = try EnvelopeParser.parse(Data(withoutKey.utf8))
        XCTAssertEqual(a, b)
        XCTAssertNil(a.outer.x3dh)
        // Encoding omits nil and sorts keys.
        let encoded: String = String(decoding: try b.outer.encoded(), as: UTF8.self)
        XCTAssertEqual(encoded, withoutKey)
        // opk_id null vs absent inside x3dh.
        let p: OuterEnvelope = try sampleOuter(kind: .prekey, opkId: nil)
        var dict: [String: Any] = try JSONSerialization.jsonObject(with: try p.encoded(), options: []) as? [String: Any] ?? [:]
        var x: [String: Any] = dict["x3dh"] as? [String: Any] ?? [:]
        XCTAssertNil(x["opk_id"])
        x["opk_id"] = NSNull()
        dict["x3dh"] = x
        let parsed: ParsedEnvelope = try EnvelopeParser.parse(try Vec.jsonBytes(dict))
        XCTAssertEqual(parsed.outer, p)
        XCTAssertNil(parsed.outer.x3dh?.opkId)
        // Slashes are not escaped.
        let m: InnerMessage = InnerMessage.text(id: "i", ts: 1, ttl: 0, text: "a/b")
        let mj: String = String(decoding: try KilitJSON.encoder().encode(m), as: UTF8.self)
        XCTAssertTrue(mj.contains("\"text\":\"a/b\""))
        XCTAssertFalse(mj.contains("\\/"))
    }

    func testStepOneRejections() throws {
        let good: OuterEnvelope = try sampleOuter(kind: .msg, opkId: nil)
        XCTAssertNoThrow(try EnvelopeParser.validate(good))
        // v != 1
        XCTAssertThrowsError(try EnvelopeParser.validate(OuterEnvelope(v: 2, kind: .msg, sid: good.sid, x3dh: nil, hdr: good.hdr, ct: good.ct)))
        // sid of the wrong decoded length
        XCTAssertThrowsError(try EnvelopeParser.validate(OuterEnvelope(kind: .msg, sid: Data(repeating: 9, count: 7), x3dh: nil, hdr: good.hdr, ct: good.ct)))
        // hdr 40 bytes → badHeader
        let shortHdr: Data = Bytes.copy(good.hdr.prefix(40))
        let e1: String? = Vec.errorName { _ = try EnvelopeParser.validate(OuterEnvelope(kind: .msg, sid: good.sid, x3dh: nil, hdr: shortHdr, ct: good.ct)) }
        XCTAssertEqual(e1, "badHeader")
        // hdr[0] = 0x02 → badHeader
        var badVersion: Data = good.hdr
        badVersion[badVersion.startIndex] = 0x02
        let e2: String? = Vec.errorName { _ = try EnvelopeParser.validate(OuterEnvelope(kind: .msg, sid: good.sid, x3dh: nil, hdr: badVersion, ct: good.ct)) }
        XCTAssertEqual(e2, "badHeader")
        // ct < 272 → bad_envelope
        let e3: String? = Vec.errorName { _ = try EnvelopeParser.validate(OuterEnvelope(kind: .msg, sid: good.sid, x3dh: nil, hdr: good.hdr, ct: Data(repeating: 1, count: 271))) }
        XCTAssertEqual(e3, "bad_envelope")
        // prekey without x3dh → bad_envelope; prekey sid is recomputed from ek.
        XCTAssertThrowsError(try EnvelopeParser.validate(OuterEnvelope(kind: .prekey, sid: good.sid, x3dh: nil, hdr: good.hdr, ct: good.ct)))
        let p: OuterEnvelope = try sampleOuter(kind: .prekey, opkId: 5)
        let carried: OuterEnvelope = OuterEnvelope(kind: .prekey, sid: Data(repeating: 0, count: 8), x3dh: p.x3dh, hdr: p.hdr, ct: p.ct)
        XCTAssertEqual(try EnvelopeParser.validate(carried).sid, X3DH.sid(ek: Data(repeating: 4, count: 32)))
        // unknown kind / bad base64url / padding in sid → bad_envelope at JSON level.
        let unknownKind: String = #"{"v":1,"kind":"other","sid":"AAAAAAAAAAA","hdr":"AQ","ct":"AQ"}"#
        XCTAssertEqual(Vec.errorName { _ = try EnvelopeParser.parse(Data(unknownKind.utf8)) }, "bad_envelope")
        let paddedSid: String = #"{"v":1,"kind":"msg","sid":"AAAAAAAAAAA=","hdr":"AQ","ct":"AQ"}"#
        XCTAssertEqual(Vec.errorName { _ = try EnvelopeParser.parse(Data(paddedSid.utf8)) }, "bad_envelope")
        XCTAssertEqual(Vec.errorName { _ = try EnvelopeParser.parse(Data("not json".utf8)) }, "bad_envelope")
    }

    // MARK: inner message

    func testInnerRoundTripVectors() throws {
        for r in try Vec.dicts(root, "inner_roundtrip") {
            let json: String = try Vec.str(r, "json")
            let m: InnerMessage = try InnerMessage.decode(Data(json.utf8))
            let encoded: Data = try KilitJSON.encoder().encode(m)
            let again: InnerMessage = try InnerMessage.decode(encoded)
            XCTAssertEqual(again, m)
            // Field-wise: every non-null key of the source survives.
            let src: [String: Any] = try Vec.object(json)
            let dst: [String: Any] = try JSONSerialization.jsonObject(with: encoded, options: []) as? [String: Any] ?? [:]
            for (k, v) in src where !(v is NSNull) {
                XCTAssertNotNil(dst[k], "key \(k) lost")
            }
        }
    }

    func testCaptureKindIsPlainString() throws {
        for kind in CaptureKindWire.all {
            let withCounters: Bool = kind != CaptureKindWire.blankingUnavailable
            let m: InnerMessage = InnerMessage(t: InnerMessageType.ctrlCapture, id: "c1", ts: 5, ttl: 0,
                                               seqFrom: withCounters ? 42 : nil, seqTo: withCounters ? 44 : nil,
                                               count: withCounters ? 3 : nil, kind: kind, ref: withCounters ? ["a", "b"] : [])
            let encoded: Data = try KilitJSON.encoder().encode(m)
            let dict: [String: Any] = try JSONSerialization.jsonObject(with: encoded, options: []) as? [String: Any] ?? [:]
            XCTAssertEqual(dict["kind"] as? String, kind)
            XCTAssertEqual(dict["seq_from"] == nil, !withCounters)
            XCTAssertEqual(dict["seq_to"] == nil, !withCounters)
            XCTAssertEqual(dict["count"] == nil, !withCounters)
            let back: InnerMessage = try InnerMessage.decode(encoded)
            XCTAssertEqual(back, m)
            XCTAssertEqual(back.kind, kind)
        }
        // Counters as explicit null decode like absent.
        let nulls: String = #"{"t":"ctrl.capture","id":"c2","ts":1,"ttl":0,"seq_from":null,"seq_to":null,"count":null,"kind":"blanking_unavailable","ref":[]}"#
        let m2: InnerMessage = try InnerMessage.decode(Data(nulls.utf8))
        XCTAssertNil(m2.seqFrom)
        XCTAssertNil(m2.count)
        XCTAssertEqual(m2.ref, [])
        // An unknown spelling still decodes as a String (the glue maps it to nil).
        let odd: String = #"{"t":"ctrl.capture","id":"c3","ts":1,"ttl":0,"kind":"something_new","ref":[]}"#
        XCTAssertEqual(try InnerMessage.decode(Data(odd.utf8)).kind, "something_new")
    }

    func testAllInnerKindsRoundTrip() throws {
        let att: InnerAttachment = InnerAttachment(blob: String(repeating: "ab", count: 16), key: Bytes.random(32),
                                                   sha256: Bytes.random(32), mime: "image/jpeg", len: 123456, w: 1200, h: 900)
        let samples: [InnerMessage] = [
            InnerMessage.text(id: "1", ts: 1760000000, ttl: 86400, text: "merhaba"),
            InnerMessage(t: InnerMessageType.image, id: "2", ts: 1760000000, ttl: 86400, att: att),
            InnerMessage(t: InnerMessageType.ctrlTimer, id: "3", ts: 1, ttl: 0, timer: 3600),
            InnerMessage(t: InnerMessageType.ctrlRead, id: "4", ts: 1, ttl: 0, ref: ["x"]),
            InnerMessage(t: InnerMessageType.ctrlDelete, id: "5", ts: 1, ttl: 0, ref: ["y"]),
            InnerMessage.resync(id: "6", ts: 1, lostSid: Data(repeating: 3, count: 8)),
        ]
        for m in samples {
            let encoded: Data = try KilitJSON.encoder().encode(m)
            XCTAssertEqual(try InnerMessage.decode(encoded), m)
        }
        let resyncJSON: String = String(decoding: try KilitJSON.encoder().encode(samples[5]), as: UTF8.self)
        XCTAssertTrue(resyncJSON.contains("\"lost_sid\":\"\(Data(repeating: 3, count: 8).base64url())\""))
        XCTAssertFalse(resyncJSON.contains("text"))
    }
}
