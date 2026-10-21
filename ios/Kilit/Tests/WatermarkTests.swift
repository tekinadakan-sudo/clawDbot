import XCTest
import CoreGraphics
@testable import Kilit

final class WatermarkTests: XCTestCase {
    private var root: [String: Any] = [:]
    private var payload: WatermarkPayload = WatermarkPayload(tag: 0, day: 0)

    override func setUpWithError() throws {
        root = try Vec.object(KilitVectors.watermark)
        let inputs: [String: Any] = try Vec.dict(root, "inputs")
        payload = WatermarkPayload(ws: try Vec.hex(inputs, "ws"), viewer: try Vec.str(inputs, "viewer"), unix: try Vec.u64(inputs, "unix"))
    }

    func testTagDayCRCAndPayload() throws {
        XCTAssertEqual(Int(payload.tag), try Vec.int(root, "tag"))
        XCTAssertEqual(Int(payload.day), try Vec.int(root, "day"))
        XCTAssertEqual(Int(payload.crc), try Vec.int(root, "crc"))
        XCTAssertEqual(Int(payload.payload16), try Vec.int(root, "payload16"))
        XCTAssertEqual(payload.payload16, UInt16(payload.tag) << 8 | UInt16(payload.day) << 4 | UInt16(payload.crc))
        let steps: [[String: Any]] = try Vec.dicts(root, "crc_steps")
        XCTAssertEqual(steps.count, 12)
        let mine: [WatermarkPayload.CRCStep] = WatermarkPayload.crc4Steps(tag: payload.tag, day: payload.day)
        XCTAssertEqual(mine.count, 12)
        for (i, s) in steps.enumerated() {
            XCTAssertEqual(Int(mine[i].bit), try Vec.int(s, "bit"), "step \(i) bit")
            XCTAssertEqual(Int(mine[i].fb), try Vec.int(s, "fb"), "step \(i) fb")
            XCTAssertEqual(Int(mine[i].crc), try Vec.int(s, "crc"), "step \(i) crc")
        }
    }

    func testWorkedExampleFromDesign() {
        // §5.9: tag 171, day 7 → crc 4, payload16 43892.
        let p: WatermarkPayload = WatermarkPayload(tag: 171, day: 7)
        XCTAssertEqual(p.crc, 4)
        XCTAssertEqual(p.payload16, 43892)
        XCTAssertEqual(Int((p.payload16 >> 8) & 0xFF), 171)
        XCTAssertEqual(Int((p.payload16 >> 4) & 0xF), 7)
    }

    func testSyncAndCellLayout() throws {
        let sync: String = try Vec.str(root, "sync")
        XCTAssertEqual(sync.count, 20)
        let bits: [Bool] = sync.map { $0 == "1" }
        XCTAssertEqual(WatermarkPayload.syncBits, bits)
        guard let cells = root["cells"] as? [[NSNumber]] else { throw VecError("cells") }
        XCTAssertEqual(cells.count, 6)
        for r in 0..<6 {
            XCTAssertEqual(cells[r].count, 6)
            for c in 0..<6 {
                XCTAssertEqual(payload.cells[r][c], cells[r][c].boolValue, "cell (\(r),\(c))")
            }
        }
        // Border placement: top row L→R, right column down, bottom row R→L, left column up.
        let order: [(row: Int, col: Int)] = WatermarkPayload.borderOrder
        XCTAssertEqual(order.count, 20)
        XCTAssertEqual(order[0].row, 0); XCTAssertEqual(order[0].col, 0)
        XCTAssertEqual(order[5].row, 0); XCTAssertEqual(order[5].col, 5)
        XCTAssertEqual(order[6].row, 1); XCTAssertEqual(order[6].col, 5)
        XCTAssertEqual(order[10].row, 5); XCTAssertEqual(order[10].col, 5)
        XCTAssertEqual(order[11].row, 5); XCTAssertEqual(order[11].col, 4)
        XCTAssertEqual(order[15].row, 5); XCTAssertEqual(order[15].col, 0)
        XCTAssertEqual(order[16].row, 4); XCTAssertEqual(order[16].col, 0)
        XCTAssertEqual(order[19].row, 1); XCTAssertEqual(order[19].col, 0)
        for (i, pos) in order.enumerated() {
            XCTAssertEqual(payload.cells[pos.row][pos.col], bits[i])
        }
        // Inner 4×4: bit 15 in (1,1) … bit 0 in (4,4).
        for k in 0..<16 {
            let bit: Bool = (payload.payload16 >> UInt16(15 - k)) & 1 == 1
            XCTAssertEqual(payload.cells[1 + k / 4][1 + k % 4], bit, "payload bit \(15 - k)")
        }
    }

    func testDeltaMapScale1ByteEqual() throws {
        let delta: [String: Any] = try Vec.dict(root, "delta")
        XCTAssertEqual(try Vec.int(delta, "cell_pt"), WatermarkPayload.cellPoints)
        XCTAssertEqual(try Vec.int(delta, "k_per_scale"), WatermarkPayload.boxWidthPerScale)
        XCTAssertEqual(try Vec.int(delta, "amplitude"), WatermarkPayload.amplitude)
        let s1: [String: Any] = try Vec.dict(delta, "scale1")
        let w: Int = try Vec.int(s1, "w")
        let h: Int = try Vec.int(s1, "h")
        XCTAssertEqual(w, 168)
        XCTAssertEqual(h, 168)
        let expected: Data = try Vec.hex(s1, "int8")
        XCTAssertEqual(expected.count, w * h)
        let map: [Int8] = payload.deltaMap(scale: 1)
        XCTAssertEqual(map.count, w * h)
        let mine: Data = Data(map.map { UInt8(bitPattern: $0) })
        XCTAssertEqual(mine, expected)
        for v in map {
            XCTAssertTrue(v >= -5 && v <= 5)
        }
    }

    func testDeltaMapScale2And3Hashes() throws {
        let delta: [String: Any] = try Vec.dict(root, "delta")
        let map2: [Int8] = payload.deltaMap(scale: 2)
        XCTAssertEqual(map2.count, 336 * 336)
        XCTAssertEqual(KDF.sha256(Data(map2.map { UInt8(bitPattern: $0) })), try Vec.hex(delta, "scale2_sha256"))
        let map3: [Int8] = payload.deltaMap(scale: 3)
        XCTAssertEqual(map3.count, 504 * 504)
        XCTAssertEqual(KDF.sha256(Data(map3.map { UInt8(bitPattern: $0) })), try Vec.hex(delta, "scale3_sha256"))
        let w3: Int = WatermarkPayload.size(scale: 3)
        for s in try Vec.dicts(delta, "samples_scale3") {
            let x: Int = try Vec.int(s, "x")
            let y: Int = try Vec.int(s, "y")
            let d: Int8 = map3[y * w3 + x]
            XCTAssertEqual(Int(d), try Vec.int(s, "delta"), "sample (\(x),\(y))")
            XCTAssertEqual(Int(WatermarkPayload.lighterByte(d)), try Vec.int(s, "lighter"))
            XCTAssertEqual(Int(WatermarkPayload.darkerByte(d)), try Vec.int(s, "darker"))
        }
    }

    /// The box filter wraps periodically: the map is seamless and the negative indices near x = 0 / y = 0
    /// read from the far edge (a plain `%` would have crashed or broken the wrap).
    func testNegativeIndexWrapIsSeamless() {
        let p: WatermarkPayload = WatermarkPayload(tag: 171, day: 7)
        let w: Int = WatermarkPayload.size(scale: 1)
        let map: [Int8] = p.deltaMap(scale: 1)
        XCTAssertEqual(map.count, w * w)
        // Re-implement the filter at a single pixel near the origin by hand with the double-mod wrap.
        let cell: Int = 28
        let half: Int = 14
        let k: Int = 4
        func base(_ x: Int, _ y: Int) -> Int {
            let b: Bool = p.cells[y / cell][x / cell]
            let left: Bool = (x % cell) < half
            return (b == left) ? 5 : -5
        }
        func wrap(_ v: Int) -> Int { ((v % w) + w) % w }
        for (x, y) in [(0, 0), (1, 0), (0, 1), (167, 167), (0, 167), (167, 0)] {
            var sum: Int = 0
            for j in -(k / 2)..<(k / 2) {
                for i in -(k / 2)..<(k / 2) {
                    sum += base(wrap(x + i), wrap(y + j))
                }
            }
            XCTAssertEqual(Int(map[y * w + x]), sum / (k * k), "pixel (\(x),\(y))")
        }
        // Lighter/darker derivation.
        XCTAssertEqual(WatermarkPayload.lighterByte(5), 5)
        XCTAssertEqual(WatermarkPayload.lighterByte(-5), 0)
        XCTAssertEqual(WatermarkPayload.darkerByte(5), 255)
        XCTAssertEqual(WatermarkPayload.darkerByte(-5), 250)
        XCTAssertEqual(WatermarkPayload.darkerByte(0), 255)
    }

    /// Overlay geometry (§5.9): a frame one tile larger on every side, with the phase applied as a bounds
    /// origin in [0,168)², always contains the content bounds.
    func testOversizedOverlayContainsContentForRandomPhases() {
        let content: CGRect = CGRect(x: 0, y: 0, width: 390, height: 844)
        var rng: SystemRandomNumberGenerator = SystemRandomNumberGenerator()
        for _ in 0..<50 {
            let phase: CGPoint = CGPoint(x: CGFloat(Double.random(in: 0..<168, using: &rng)),
                                         y: CGFloat(Double.random(in: 0..<168, using: &rng)))
            let frame: CGRect = content.insetBy(dx: -168, dy: -168)
            // Shifting the pattern by `phase` inside the frame leaves the covered region = frame; the frame
            // offset by at most one tile in either direction still contains the content.
            let shifted: CGRect = frame.offsetBy(dx: -phase.x, dy: -phase.y)
            XCTAssertTrue(frame.contains(content))
            XCTAssertTrue(shifted.contains(content), "phase \(phase)")
            let shiftedBack: CGRect = frame.offsetBy(dx: phase.x, dy: phase.y)
            XCTAssertTrue(shiftedBack.contains(content), "phase \(phase)")
        }
    }
}
