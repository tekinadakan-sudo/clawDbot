//  CaptureGlueTests.swift
//  Kilit — WP8 tests (§5.12): per-peer `seq` monotonicity, the 2 s coalescing
//  window with an injected clock and a recording `sendControl` stub,
//  `blanking_unavailable` consuming no `seq`, and gap rendering from
//  `lastPeerCaptureSeq`.

import Foundation
import XCTest
@testable import Kilit

final class RecordingCaptureSink: CaptureGlueSink {
    private(set) var recorded: [(event: CaptureEvent, row: Message)] = []
    private(set) var sent: [(peer: String, inner: InnerMessage)] = []

    init() {}

    func recordLocalCapture(_ event: CaptureEvent, row: Message) {
        recorded.append((event: event, row: row))
    }

    func sendControl(peer: String, inner: InnerMessage) {
        sent.append((peer: peer, inner: inner))
    }
}

final class CaptureGlueTests: XCTestCase {

    @MainActor
    private func makeGlue(now: UInt64 = 1_700_000_000, seq: [String: UInt32] = [:])
        -> (CaptureGlue, RecordingCaptureSink, ManualClock) {
        let clock: ManualClock = ManualClock(now: now)
        let sink: RecordingCaptureSink = RecordingCaptureSink()
        let glue: CaptureGlue = CaptureGlue(clock: clock, sink: sink, seq: seq, automaticFlush: false)
        return (glue, sink, clock)
    }

    private func date(_ clock: ManualClock) -> Date {
        Date(timeIntervalSince1970: TimeInterval(clock.now))
    }

    @MainActor
    func testSequenceIsMonotonicPerPeer() {
        let (glue, sink, clock) = makeGlue(seq: ["bob": 4])
        glue.activePeer = "alice"
        glue.handle(.screenshot, at: date(clock))
        glue.handle(.recordingStarted, at: date(clock))
        glue.activePeer = "bob"
        glue.handle(.screenshot, at: date(clock))
        glue.activePeer = "alice"
        glue.handle(.recordingStopped, at: date(clock))

        XCTAssertEqual(glue.seq["alice"], 3)
        XCTAssertEqual(glue.seq["bob"], 5)                 // continues from the persisted value
        XCTAssertEqual(sink.recorded.map { $0.event.seq }, [1, 2, 5, 3])
        XCTAssertEqual(sink.recorded.map { $0.event.peer }, ["alice", "alice", "bob", "alice"])
        XCTAssertEqual(sink.recorded.map { $0.event.kind },
                       ["screenshot", "recording_started", "screenshot", "recording_stopped"])
        for entry in sink.recorded {
            XCTAssertEqual(entry.row.kind, .capture)
            XCTAssertEqual(entry.row.author, .me)
            XCTAssertEqual(entry.row.capture, entry.event)
        }
    }

    @MainActor
    func testEventsOutsideAConversationAreDropped() {
        let (glue, sink, clock) = makeGlue()
        glue.activePeer = nil
        glue.handle(.screenshot, at: date(clock))
        XCTAssertTrue(sink.recorded.isEmpty)
        XCTAssertTrue(glue.seq.isEmpty)
    }

    @MainActor
    func testBlankingUnavailableConsumesNoSequenceAndCarriesNoCounters() {
        let (glue, sink, clock) = makeGlue()
        glue.activePeer = "alice"
        glue.visibleMessageIds = ["m1"]
        XCTAssertTrue(glue.markBlankingReport(peer: "alice"))
        XCTAssertFalse(glue.markBlankingReport(peer: "alice"))   // once per launch per peer
        XCTAssertTrue(glue.markBlankingReport(peer: "bob"))
        glue.handle(.blankingUnavailable, at: date(clock))
        glue.handle(.screenshot, at: date(clock))

        XCTAssertNil(sink.recorded[0].event.seq)
        XCTAssertEqual(sink.recorded[0].event.ref, [])
        XCTAssertEqual(sink.recorded[1].event.seq, 1)
        XCTAssertEqual(sink.recorded[1].event.ref, ["m1"])

        glue.flush(force: true)
        XCTAssertEqual(sink.sent.count, 2)
        let blanking: InnerMessage = sink.sent[0].inner
        XCTAssertEqual(blanking.t, InnerMessageType.ctrlCapture)
        XCTAssertEqual(blanking.kind, CaptureKindWire.blankingUnavailable)
        XCTAssertNil(blanking.seqFrom)
        XCTAssertNil(blanking.seqTo)
        XCTAssertNil(blanking.count)
        XCTAssertEqual(blanking.ref, [])
        let shot: InnerMessage = sink.sent[1].inner
        XCTAssertEqual(shot.kind, CaptureKindWire.screenshot)
        XCTAssertEqual(shot.seqFrom, 1)
        XCTAssertEqual(shot.seqTo, 1)
        XCTAssertEqual(shot.count, 1)
    }

    @MainActor
    func testTwoSecondCoalescingWindow() {
        let (glue, sink, clock) = makeGlue()
        glue.activePeer = "alice"
        glue.visibleMessageIds = ["a", "b"]
        glue.handle(.screenshot, at: date(clock))
        clock.advance(1)
        glue.visibleMessageIds = ["b", "c"]
        glue.handle(.screenshot, at: date(clock))
        glue.flush(force: false)                                  // window still open at t+1
        XCTAssertTrue(sink.sent.isEmpty)
        XCTAssertTrue(glue.hasPendingWindows)

        clock.advance(1)                                          // t+2: closed
        glue.flush(force: false)
        XCTAssertEqual(sink.sent.count, 1)
        let inner: InnerMessage = sink.sent[0].inner
        XCTAssertEqual(sink.sent[0].peer, "alice")
        XCTAssertEqual(inner.t, InnerMessageType.ctrlCapture)
        XCTAssertEqual(inner.kind, "screenshot")
        XCTAssertEqual(inner.seqFrom, 1)
        XCTAssertEqual(inner.seqTo, 2)
        XCTAssertEqual(inner.count, 2)
        XCTAssertEqual(inner.ref, ["a", "b", "c"])                // merged, deduplicated
        XCTAssertEqual(inner.ttl, 0)
        XCTAssertFalse(glue.hasPendingWindows)

        glue.handle(.screenshot, at: date(clock))                 // a new window after the flush
        clock.advance(2)
        glue.flush(force: false)
        XCTAssertEqual(sink.sent.count, 2)
        XCTAssertEqual(sink.sent[1].inner.seqFrom, 3)
        XCTAssertEqual(sink.sent[1].inner.seqTo, 3)
        XCTAssertEqual(sink.sent[1].inner.count, 1)
    }

    @MainActor
    func testWindowsAreSeparatePerKindAndPeer() {
        let (glue, sink, clock) = makeGlue()
        glue.activePeer = "alice"
        glue.handle(.screenshot, at: date(clock))
        glue.handle(.recordingStarted, at: date(clock))
        glue.activePeer = "bob"
        glue.handle(.screenshot, at: date(clock))
        clock.advance(2)
        glue.flush(force: false)
        XCTAssertEqual(sink.sent.count, 3)
        XCTAssertEqual(Set(sink.sent.map { $0.peer + ":" + ($0.inner.kind ?? "") }),
                       Set(["alice:screenshot", "alice:recording_started", "bob:screenshot"]))
    }

    @MainActor
    func testReportsDisabledKeepsLocalLogOnly() {
        let (glue, sink, clock) = makeGlue()
        glue.activePeer = "alice"
        glue.reportsEnabled = false
        glue.handle(.screenshot, at: date(clock))
        clock.advance(3)
        glue.flush(force: true)
        XCTAssertEqual(sink.recorded.count, 1)
        XCTAssertTrue(sink.sent.isEmpty)
        XCTAssertEqual(glue.seq["alice"], 1)
    }

    @MainActor
    func testWireConversions() {
        XCTAssertEqual(CaptureGlue.wireKind("recording_started"), .recordingStarted)
        XCTAssertEqual(CaptureGlue.wireKind("blanking_unavailable"), .blankingUnavailable)
        XCTAssertNil(CaptureGlue.wireKind("recordingStarted"))
        XCTAssertNil(CaptureGlue.wireKind("mirroring"))
        XCTAssertEqual(CaptureGlue.wireString(.recordingStopped), CaptureKindWire.recordingStopped)
        for raw in CaptureKindWire.all {
            XCTAssertNotNil(CaptureGlue.wireKind(raw), raw)
        }
    }

    @MainActor
    func testGapRenderingFromLastPeerCaptureSeq() {
        XCTAssertFalse(CaptureGlue.hasGap(lastPeerCaptureSeq: nil, seqFrom: 1))
        XCTAssertTrue(CaptureGlue.hasGap(lastPeerCaptureSeq: nil, seqFrom: 2))
        XCTAssertFalse(CaptureGlue.hasGap(lastPeerCaptureSeq: 4, seqFrom: 5))
        XCTAssertTrue(CaptureGlue.hasGap(lastPeerCaptureSeq: 4, seqFrom: 7))
        XCTAssertFalse(CaptureGlue.hasGap(lastPeerCaptureSeq: 4, seqFrom: nil))      // blanking_unavailable

        func row(_ id: String, kind: String, from: UInt32?, to: UInt32?, at: UInt64) -> Message {
            let event: CaptureEvent = CaptureEvent(peer: "alice", seq: to, kind: kind, ts: at, ref: [],
                                                   seqFrom: from, seqTo: to, count: from == nil ? nil : 1)
            return MessageSync.systemRow(id: id, peer: "alice", kind: .capture, ts: at, now: at, state: .received,
                                         capture: event)
        }
        let messages: [Message] = [
            row("r1", kind: "screenshot", from: 1, to: 2, at: 10),
            row("r2", kind: "blanking_unavailable", from: nil, to: nil, at: 11),
            row("r3", kind: "recording_started", from: 3, to: 3, at: 12),
            row("r4", kind: "screenshot", from: 6, to: 6, at: 13),              // 4 and 5 unreported
            row("r5", kind: "screenshot", from: 7, to: 7, at: 14),
        ]
        XCTAssertEqual(CaptureGlue.gapRowIds(messages), Set(["r4"]))
    }
}
