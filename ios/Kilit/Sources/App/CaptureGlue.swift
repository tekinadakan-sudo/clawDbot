//  CaptureGlue.swift
//  Kilit — App/ (WP8), §5.6 / §3.4.
//
//  Maps `Security.CaptureEventKind` → the per-conversation `captureSeq[peer]`
//  (persisted in index.json), the local capture log, the "Sen ekran görüntüsü
//  aldın" system row and the coalesced `ctrl.capture` control (one message per
//  2 s window per (peer, kind), range `seq_from…seq_to`, `count`, merged `ref`).
//  This is the ONLY place that converts between `CaptureEventKind` and the inner
//  message's plain-String `kind` (`rawValue` / `init(rawValue:)`).
//  `blanking_unavailable` consumes no `seq`, carries `ref = []`, and is emitted
//  once per app launch per peer (`markBlankingReport(peer:)`).

import Foundation
import OSLog

/// Persistence + transport behind the glue: `SyncCaptureSink` in the app, a
/// recorder in `CaptureGlueTests`.
protocol CaptureGlueSink: AnyObject {
    /// Persists the advanced `captureSeq[peer]`, appends `event` to the capture
    /// log and `row` to `conv/<peer>.json`.
    func recordLocalCapture(_ event: CaptureEvent, row: Message)
    /// Sends one coalesced `ctrl.capture` inner message to `peer`.
    func sendControl(peer: String, inner: InnerMessage)
}

@MainActor
final class CaptureGlue {

    nonisolated static let coalesceWindow: UInt64 = ControlCoalescer.captureWindow

    private let clock: KilitClock
    private let sink: CaptureGlueSink
    private let automaticFlush: Bool

    /// Highest `seq` handed out per peer (loaded from `index.json` at launch).
    private(set) var seq: [String: UInt32]
    private var coalescer: ControlCoalescer = ControlCoalescer()
    private var blankingReported: Set<String> = []
    private var flushTask: Task<Void, Never>?

    /// The conversation on screen; events outside a conversation are not attributable and are dropped.
    var activePeer: String?
    /// Message ids visible during the window (`ref`).
    var visibleMessageIds: [String] = []
    /// Settings › capture reports to peer (the local log and row are kept regardless).
    var reportsEnabled: Bool = true

    init(clock: KilitClock, sink: CaptureGlueSink, seq: [String: UInt32] = [:], automaticFlush: Bool = true) {
        self.clock = clock
        self.sink = sink
        self.seq = seq
        self.automaticFlush = automaticFlush
    }

    // MARK: - Conversions (§3.4)

    /// Wire spelling → kind; nil for an unknown spelling (Diagnostics logs it, no row renders).
    nonisolated static func wireKind(_ raw: String) -> CaptureEventKind? {
        CaptureEventKind(rawValue: raw)
    }

    nonisolated static func wireString(_ kind: CaptureEventKind) -> String {
        kind.rawValue
    }

    // MARK: - Events

    /// `CaptureMonitor.onEvent` sink.
    func handle(_ kind: CaptureEventKind, at timestamp: Date) {
        guard let peer = activePeer else { return }
        let ts: UInt64 = UInt64(max(0, timestamp.timeIntervalSince1970))
        var number: UInt32? = nil
        if kind.consumesSequenceNumber {
            let next: UInt32 = (seq[peer] ?? 0) &+ 1
            seq[peer] = next
            number = next
        }
        let ref: [String] = kind.consumesSequenceNumber ? visibleMessageIds : []
        let event: CaptureEvent = CaptureEvent(peer: peer, seq: number, kind: kind.rawValue, ts: ts, ref: ref)
        let row: Message = MessageSync.systemRow(id: Identifiers.messageId(), peer: peer, kind: .capture, ts: ts,
                                                 now: clock.now, state: .sent, author: .me, capture: event)
        sink.recordLocalCapture(event, row: row)
        guard reportsEnabled else { return }
        coalescer.addCapture(peer: peer, kind: kind.rawValue, seq: number, ref: ref, now: clock.now)
        scheduleFlush()
    }

    /// True the first time this launch sees `peer` while `isProtected == false`;
    /// the caller then calls `CaptureMonitor.reportBlankingUnavailable()`.
    @discardableResult
    func markBlankingReport(peer: String) -> Bool {
        if blankingReported.contains(peer) { return false }
        blankingReported.insert(peer)
        return true
    }

    /// Closed windows (all of them when `force`) become `ctrl.capture` controls.
    func flush(force: Bool) {
        let due: [CaptureWindow] = coalescer.dueCaptures(now: clock.now, force: force)
        for window in due {
            let inner: InnerMessage = window.inner(id: Identifiers.messageId(), ts: clock.now)
            sink.sendControl(peer: window.peer, inner: inner)
        }
        if !coalescer.isEmpty { scheduleFlush() }
    }

    var hasPendingWindows: Bool { !coalescer.isEmpty }

    private func scheduleFlush() {
        guard automaticFlush, flushTask == nil else { return }
        flushTask = Task { [weak self] in
            try? await Task.sleep(for: .seconds(Double(CaptureGlue.coalesceWindow)))
            guard let self, !Task.isCancelled else { return }
            self.flushTask = nil
            self.flush(force: false)
        }
    }

    // MARK: - Gap rendering (§5.6)

    /// A peer report whose `seq_from` skips past the highest `seq_to` seen so far
    /// renders "Bildirilmeyen olay". `blanking_unavailable` (no counters) never does.
    nonisolated static func hasGap(lastPeerCaptureSeq: UInt32?, seqFrom: UInt32?) -> Bool {
        guard let from = seqFrom else { return false }
        return from > (lastPeerCaptureSeq ?? 0) &+ 1
    }

    /// Ids of the peer capture rows (in local order) preceded by a gap.
    nonisolated static func gapRowIds(_ messages: [Message]) -> Set<String> {
        var highest: UInt32? = nil
        var gaps: Set<String> = []
        for m in messages where m.kind == .capture && m.author == .peer {
            guard let event = m.capture else { continue }
            if hasGap(lastPeerCaptureSeq: highest, seqFrom: event.seqFrom) { gaps.insert(m.id) }
            if let to = event.seqTo { highest = max(highest ?? 0, to) }
        }
        return gaps
    }
}

// MARK: - Production sink (MessageSync)

/// Forwards the glue's calls onto the `MessageSync` actor.
final class SyncCaptureSink: CaptureGlueSink {
    private let sync: MessageSync

    init(sync: MessageSync) {
        self.sync = sync
    }

    func recordLocalCapture(_ event: CaptureEvent, row: Message) {
        let s: MessageSync = sync
        Task { await s.persistLocalCapture(event, row: row) }
    }

    func sendControl(peer: String, inner: InnerMessage) {
        let s: MessageSync = sync
        Task { await s.sendControl(peer: peer, inner: inner) }
    }
}

extension MessageSync {
    /// Local event: `captureSeq[peer]`, capture log and the "Sen …" row in one commit.
    func persistLocalCapture(_ event: CaptureEvent, row: Message) {
        guard store.isOpen else { return }
        var conv: ConversationDocument = loadConversation(event.peer)
        conv.append(row)
        let peer: String = event.peer
        do {
            try store.commit([try DocumentWrite(path: LocalStore.conversationPath(peer), value: conv)]) { idx in
                idx.appendCapture(event)
                if let s = event.seq {
                    idx.captureSeq[peer] = max(idx.captureSeq[peer] ?? 0, s)
                }
            }
            emit(.conversationChanged(peer: peer))
        } catch {
            MessageSync.logger.error("capture persist failed: \(String(describing: error), privacy: .public)")
        }
    }

    /// One already-coalesced `ctrl.capture`: queued as a control outbox item (priority 1, after content).
    func sendControl(peer: String, inner: InnerMessage) async {
        guard store.isOpen, store.index.settings.captureReports else { return }
        let item: OutboxItem = OutboxItem(id: Identifiers.hex32(), payload: .control(to: peer, inner: inner),
                                          priority: 1, createdAt: clock.now)
        do {
            try store.commitIndex { idx in idx.outbox.append(item) }
        } catch {
            MessageSync.logger.error("control enqueue failed: \(String(describing: error), privacy: .public)")
            return
        }
        await pumpOutbox()
    }
}
