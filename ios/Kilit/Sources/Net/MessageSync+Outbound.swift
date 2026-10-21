import Foundation
import OSLog

// MARK: - Outbound: encrypt → persist state + cached envelope → POST; outbox; controls; attachments

enum SendResult: Equatable {
    case done
    case retry
    case abandon
}

extension OutboxItem {
    var peer: String? {
        switch payload {
        case .envelope(let to, _, _): return to
        case .control(let to, _): return to
        case .deleteBlob: return nil
        }
    }
}

extension MessageSync {
    // MARK: sending (§3.5 send pipeline, §5.4)

    /// Text message with the conversation's current timer as `ttl`. Returns the outer `msg_id`.
    @discardableResult
    func sendText(to peer: String, text: String) async throws -> String {
        let ttl: UInt32 = store.index.conversation(peer)?.timer ?? store.index.settings.defaultTimer
        let inner: InnerMessage = InnerMessage.text(id: Identifiers.messageId(), ts: clock.now, ttl: ttl, text: text)
        return try await enqueueContent(peer: peer, inner: inner, newRow: true)
    }

    /// Image: upload first (fresh `blob_id` + `fileKey`, ≤ 3 attempts on `409 blob_exists`), then the message.
    @discardableResult
    func sendImage(to peer: String, image: NormalizedImage) async throws -> String {
        guard store.isOpen else { throw SyncError.notOpen }
        if let c = store.index.contact(peer), c.blocked { throw SyncError.blocked(peer: peer) }
        if store.index.conversation(peer)?.pendingKeyChange != nil { throw SyncError.keyChangePending(peer: peer) }
        let sealed: SealedAttachment = try await AttachmentUploader.upload(plaintext: image.data, mime: NormalizedImage.mime,
                                                                           recipient: peer, api: api, keySource: keySource)
        let att: InnerAttachment = InnerAttachment(blob: sealed.blobIdHex, key: sealed.fileKey, sha256: sealed.sha256,
                                                   mime: sealed.mime, len: sealed.len, w: image.width, h: image.height)
        // The sender keeps its own ciphertext so the image can be viewed locally (the sender never deletes the server blob).
        try blobs.write(id: sealed.blobIdHex, ciphertext: sealed.blob)
        let ttl: UInt32 = store.index.conversation(peer)?.timer ?? store.index.settings.defaultTimer
        let inner: InnerMessage = InnerMessage(t: InnerMessageType.image, id: Identifiers.messageId(), ts: clock.now, ttl: ttl, att: att)
        return try await enqueueContent(peer: peer, inner: inner, newRow: true)
    }

    /// Sending session (§3.2 rule) or a fresh initiation.
    func ensureSendingSession(peer: String) async throws -> SessionDocument {
        let doc: SessionDocument = try sessions.load(peer: peer)
        if doc.peer.sendingSession() != nil { return doc }
        return try await initiateSession(peer: peer, lostSid: nil)
    }

    /// Encrypts on the sending session, persists the advanced state and the cached envelope (write-before-send),
    /// appends the message row (`newRow`) and the outbox item, then pumps. Returns the outer `msg_id`.
    func enqueueContent(peer: String, inner: InnerMessage, newRow: Bool) async throws -> String {
        guard store.isOpen else { throw SyncError.notOpen }
        if let c = store.index.contact(peer), c.blocked { throw SyncError.blocked(peer: peer) }
        if store.index.conversation(peer)?.pendingKeyChange != nil { throw SyncError.keyChangePending(peer: peer) }
        let now: UInt64 = clock.now
        var doc: SessionDocument = try await ensureSendingSession(peer: peer)
        let msgId: String = Identifiers.hex32()
        let cached: CachedEnvelope = try SessionStore.encrypt(doc: &doc, peer: peer, inner: inner, msgId: msgId,
                                                              local: local, now: now)
        var conv: ConversationDocument = loadConversation(peer)
        if newRow {
            let kind: MessageKind = inner.t == InnerMessageType.image ? .image : .text
            var m: Message = Message(id: inner.id, conversationID: peer, author: .me, kind: kind, ts: inner.ts, ttl: inner.ttl,
                                     state: .outbox, text: inner.text, att: inner.att, sentOnSid: cached.sid)
            if let att = inner.att { m.blobDownloaded = blobs.exists(id: att.blob) }
            conv.append(m)
            _ = conv.state.rememberMessage(author: .me, id: inner.id, now: now)
        }
        conv.recordSent(id: inner.id, sid: cached.sid, at: now)
        let item: OutboxItem = OutboxItem(id: msgId, payload: .envelope(to: peer, msgId: msgId, innerId: inner.id),
                                          priority: 0, createdAt: now)
        try store.commit([try sessions.write(peer: peer, doc),
                          try DocumentWrite(path: LocalStore.conversationPath(peer), value: conv)]) { idx in
            idx.outbox.append(item)
            let i: Int = idx.conversationIndex(peer, now: now)
            idx.conversations[i].lastActivityAt = now
        }
        emit(.conversationChanged(peer: peer))
        await pumpOutbox()
        return msgId
    }

    // MARK: outbox (§5.4: 5 s–10 min backoff, content before control, per-peer order)

    func pumpOutbox() async {
        guard !pumping, store.isOpen else { return }
        pumping = true
        reauthenticatedThisPump = false
        defer { pumping = false }
        let ordered: [OutboxItem] = store.index.outbox.enumerated().sorted { a, b in
            if a.element.priority != b.element.priority { return a.element.priority < b.element.priority }
            if a.element.createdAt != b.element.createdAt { return a.element.createdAt < b.element.createdAt }
            return a.offset < b.offset
        }.map { $0.element }
        var blockedPeers: Set<String> = []
        for item in ordered {
            guard store.isOpen else { break }
            guard store.index.outbox.contains(where: { $0.id == item.id }) else { continue }
            let now: UInt64 = clock.now
            guard item.nextAttemptAt <= now else { continue }
            if let p = item.peer, blockedPeers.contains(p) { continue }
            let outcome: (id: String, result: SendResult) = await sendItem(item)
            switch outcome.result {
            case .done:
                break
            case .retry:
                if let p = item.peer { blockedPeers.insert(p) }
                let at: UInt64 = clock.now
                _ = try? store.commitIndex { idx in
                    if let i = idx.outbox.firstIndex(where: { $0.id == outcome.id }) {
                        idx.outbox[i].attempts += 1
                        idx.outbox[i].nextAttemptAt = at + Backoff.outbox(attempts: idx.outbox[i].attempts)
                    }
                }
            case .abandon:
                _ = try? store.commitIndex { idx in idx.outbox.removeAll { $0.id == outcome.id } }
            }
        }
        scheduleOutboxWake()
    }

    func scheduleOutboxWake() {
        outboxWake?.cancel()
        outboxWake = nil
        let now: UInt64 = clock.now
        guard let earliest = store.index.outbox.map({ $0.nextAttemptAt }).min() else { return }
        let delay: Double = earliest > now ? Double(earliest - now) : 1
        outboxWake = Task { [weak self] in
            guard let self = self else { return }
            await self.wakeOutbox(after: delay)
        }
    }

    func wakeOutbox(after delay: Double) async {
        do {
            try await sleeper.sleep(seconds: delay)
        } catch {
            return
        }
        outboxWake = nil
        await pumpOutbox()
    }

    /// Sends one item; the returned id is the item to update (a control is converted into an envelope item).
    func sendItem(_ item: OutboxItem) async -> (id: String, result: SendResult) {
        switch item.payload {
        case .envelope(let to, let msgId, let innerId):
            return (item.id, await sendEnvelope(to: to, msgId: msgId, innerId: innerId, itemId: item.id))
        case .control(let to, let inner):
            let now: UInt64 = clock.now
            do {
                var doc: SessionDocument = try await ensureSendingSession(peer: to)
                let msgId: String = Identifiers.hex32()
                _ = try SessionStore.encrypt(doc: &doc, peer: to, inner: inner, msgId: msgId, local: local, now: now)
                var replacement: OutboxItem = OutboxItem(id: msgId, payload: .envelope(to: to, msgId: msgId, innerId: inner.id),
                                                         priority: 1, createdAt: item.createdAt)
                replacement.attempts = item.attempts
                let itemId: String = item.id
                let replaced: OutboxItem = replacement
                try store.commit([try sessions.write(peer: to, doc)]) { idx in
                    idx.outbox.removeAll { $0.id == itemId }
                    idx.outbox.append(replaced)
                }
                return (msgId, await sendEnvelope(to: to, msgId: msgId, innerId: inner.id, itemId: msgId))
            } catch let e as APIError {
                if e.status == 401 { await reauthenticateIfNeeded() }
                return (item.id, e.isTransient ? .retry : .abandon)
            } catch let e as SyncError {
                MessageSync.logger.notice("control dropped: \(String(describing: e), privacy: .public)")
                return (item.id, .abandon)
            } catch {
                return (item.id, .retry)
            }
        case .deleteBlob(let id):
            do {
                try await api.deleteBlob(blobID: id)
                return (item.id, .done)
            } catch let e as APIError {
                if e.status == 401 { await reauthenticateIfNeeded() }
                return (item.id, e.isTransient ? .retry : .abandon)
            } catch {
                return (item.id, .retry)
            }
        }
    }

    func sendEnvelope(to peer: String, msgId: String, innerId: String, itemId: String) async -> SendResult {
        let cached: CachedEnvelope?
        do {
            cached = try sessions.cached(peer: peer, msgId: msgId)
        } catch {
            return .retry
        }
        guard let envelope = cached else { return .abandon }
        do {
            _ = try await api.send(SendRequest(to: peer, msgId: msgId, envelope: envelope.envelope))
        } catch let e as APIError {
            if e.status == 401 { await reauthenticateIfNeeded() }
            if e.isTransient { return .retry }
            MessageSync.logger.error("send rejected \(e.status ?? 0, privacy: .public) \(e.code ?? "", privacy: .public)")
            return .abandon
        } catch {
            return .retry
        }
        let now: UInt64 = clock.now
        do {
            var writes: [DocumentWrite] = []
            var conv: ConversationDocument = loadConversation(peer)
            if let i = conv.index(id: innerId, author: .me) {
                conv.messages[i].markSent(at: now)
                writes.append(try DocumentWrite(path: LocalStore.conversationPath(peer), value: conv))
            }
            var doc: SessionDocument = try sessions.load(peer: peer)
            doc.pendingSends.removeAll { $0.msgId == msgId }
            writes.append(try sessions.write(peer: peer, doc))
            try store.commit(writes) { idx in idx.outbox.removeAll { $0.id == itemId } }
            emit(.conversationChanged(peer: peer))
        } catch {
            MessageSync.logger.error("post-send write failed: \(String(describing: error), privacy: .public)")
        }
        return .done
    }

    // MARK: controls (§3.4 coalescing)

    /// `CaptureGlue` reports one event (`kind` = wire spelling; `seq` nil for `blanking_unavailable`).
    func reportCapture(peer: String, kind: String, seq: UInt32?, ref: [String]) {
        guard store.isOpen, store.index.settings.captureReports else { return }
        coalescer.addCapture(peer: peer, kind: kind, seq: seq, ref: ref, now: clock.now)
        scheduleControlFlush()
    }

    /// Ids first revealed in this window, batched into one `ctrl.read` per 5 s (only when read receipts are on).
    func reportRevealed(peer: String, ids: [String]) {
        guard store.isOpen, store.index.settings.readReceipts, !ids.isEmpty else { return }
        coalescer.addRead(peer: peer, ids: ids, now: clock.now)
        scheduleControlFlush()
    }

    func scheduleControlFlush() {
        guard controlFlush == nil else { return }
        controlFlush = Task { [weak self] in
            guard let self = self else { return }
            await self.controlFlushAfterDelay()
        }
    }

    func controlFlushAfterDelay() async {
        do {
            try await sleeper.sleep(seconds: MessageSync.controlFlushDelay)
        } catch {
            controlFlush = nil
            return
        }
        controlFlush = nil
        await flushControls(force: false)
        if !coalescer.isEmpty { scheduleControlFlush() }
    }

    /// Closed windows become `.control` outbox items (priority 1, encrypted when dequeued, after content).
    func flushControls(force: Bool) async {
        guard store.isOpen else { return }
        let now: UInt64 = clock.now
        let captures: [CaptureWindow] = coalescer.dueCaptures(now: now, force: force)
        let reads: [ReadBatch] = coalescer.dueReads(now: now, force: force)
        guard !captures.isEmpty || !reads.isEmpty else { return }
        var items: [OutboxItem] = []
        for w in captures {
            let inner: InnerMessage = w.inner(id: Identifiers.messageId(), ts: now)
            items.append(OutboxItem(id: Identifiers.hex32(), payload: .control(to: w.peer, inner: inner), priority: 1, createdAt: now))
        }
        for r in reads {
            let inner: InnerMessage = InnerMessage(t: InnerMessageType.ctrlRead, id: Identifiers.messageId(), ts: now, ttl: 0, ref: r.ids)
            items.append(OutboxItem(id: Identifiers.hex32(), payload: .control(to: r.peer, inner: inner), priority: 1, createdAt: now))
        }
        do {
            try store.commitIndex { idx in idx.outbox.append(contentsOf: items) }
        } catch {
            MessageSync.logger.error("control enqueue failed: \(String(describing: error), privacy: .public)")
            return
        }
        await pumpOutbox()
    }

    /// Sets the conversation timer (0 = off), inserts the system row and sends `ctrl.timer`.
    func setTimer(peer: String, seconds: UInt32) async throws {
        guard store.isOpen else { throw SyncError.notOpen }
        let now: UInt64 = clock.now
        var conv: ConversationDocument = loadConversation(peer)
        let inner: InnerMessage = InnerMessage(t: InnerMessageType.ctrlTimer, id: Identifiers.messageId(), ts: now, ttl: 0, timer: seconds)
        conv.append(MessageSync.systemRow(id: inner.id, peer: peer, kind: .timer, ts: now, now: now, state: .sent, author: .me, timer: seconds))
        let item: OutboxItem = OutboxItem(id: Identifiers.hex32(), payload: .control(to: peer, inner: inner), priority: 1, createdAt: now)
        try store.commit([try DocumentWrite(path: LocalStore.conversationPath(peer), value: conv)]) { idx in
            let i: Int = idx.conversationIndex(peer, now: now)
            idx.conversations[i].timer = seconds
            idx.outbox.append(item)
        }
        emit(.conversationChanged(peer: peer))
        await pumpOutbox()
    }

    /// "Benim için ve karşı taraf için sil": the only `ctrl.delete` source; own messages only.
    func deleteForBoth(peer: String, ids: [String]) async throws {
        guard store.isOpen else { throw SyncError.notOpen }
        let now: UInt64 = clock.now
        var conv: ConversationDocument = loadConversation(peer)
        let removed: [Message] = conv.remove(ids: ids, author: .me)
        guard !removed.isEmpty else { return }
        for m in removed {
            if let att = m.att { blobs.delete(id: att.blob) }
        }
        let inner: InnerMessage = InnerMessage(t: InnerMessageType.ctrlDelete, id: Identifiers.messageId(), ts: now, ttl: 0,
                                               ref: removed.map { $0.id })
        let item: OutboxItem = OutboxItem(id: Identifiers.hex32(), payload: .control(to: peer, inner: inner), priority: 1, createdAt: now)
        try store.commit([try DocumentWrite(path: LocalStore.conversationPath(peer), value: conv)]) { idx in
            idx.outbox.append(item)
        }
        emit(.conversationChanged(peer: peer))
        await pumpOutbox()
    }

    /// Local-only delete ("Benim için sil"); sends nothing.
    func deleteLocally(peer: String, ids: [String]) throws {
        guard store.isOpen else { throw SyncError.notOpen }
        var conv: ConversationDocument = loadConversation(peer)
        var removed: [Message] = conv.remove(ids: ids, author: .me)
        removed += conv.remove(ids: ids, author: .peer)
        guard !removed.isEmpty else { return }
        for m in removed {
            if let att = m.att { blobs.delete(id: att.blob) }
        }
        try store.commit([try DocumentWrite(path: LocalStore.conversationPath(peer), value: conv)])
        emit(.conversationChanged(peer: peer))
    }

    /// First reveal of a peer message: fixes `expiresAt`, moves to `.revealed`, reports a read receipt.
    func markRevealed(peer: String, id: String) throws {
        guard store.isOpen else { throw SyncError.notOpen }
        let now: UInt64 = clock.now
        var conv: ConversationDocument = loadConversation(peer)
        guard let i = conv.index(id: id, author: .peer), conv.messages[i].firstRevealedAt == nil else { return }
        conv.messages[i].markRevealed(at: now)
        try store.commit([try DocumentWrite(path: LocalStore.conversationPath(peer), value: conv)])
        reportRevealed(peer: peer, ids: [id])
        emit(.conversationChanged(peer: peer))
    }

    // MARK: attachments (§3.5b receive pipeline)

    func downloadAttachment(peer: String, messageId: String) async {
        guard store.isOpen else { return }
        let before: ConversationDocument = loadConversation(peer)
        guard let i = before.index(id: messageId, author: .peer), let att = before.messages[i].att,
              !before.messages[i].blobDownloaded, !before.messages[i].blobExpired else { return }
        var downloaded: Bool = false
        var expired: Bool = false
        do {
            downloaded = try await AttachmentDownloader.download(att: att, api: api, blobs: blobs)
            expired = !downloaded
        } catch AttachmentError.expired, AttachmentError.badId {
            expired = true
        } catch let e as APIError {
            if e.status == 401 { await reauthenticateIfNeeded() }
            return
        } catch {
            return
        }
        var conv: ConversationDocument = loadConversation(peer)
        guard let j = conv.index(id: messageId, author: .peer) else {
            if downloaded { blobs.delete(id: att.blob) }
            return
        }
        conv.messages[j].blobDownloaded = downloaded
        conv.messages[j].blobExpired = expired
        let now: UInt64 = clock.now
        let del: OutboxItem = OutboxItem(id: Identifiers.hex32(), payload: .deleteBlob(id: att.blob), priority: 1, createdAt: now)
        do {
            try store.commit([try DocumentWrite(path: LocalStore.conversationPath(peer), value: conv)]) { idx in
                if downloaded { idx.outbox.append(del) }
            }
        } catch {
            MessageSync.logger.error("attachment state write failed: \(String(describing: error), privacy: .public)")
            return
        }
        emit(.conversationChanged(peer: peer))
        if downloaded { await pumpOutbox() }
    }

    /// Retries every image whose blob is neither downloaded nor expired (launch, foreground).
    func retryDownloads() async {
        for c in store.index.conversations {
            let doc: ConversationDocument = loadConversation(c.peer)
            for m in doc.messages where m.author == .peer && m.kind == .image && !m.blobDownloaded && !m.blobExpired {
                await downloadAttachment(peer: c.peer, messageId: m.id)
            }
        }
    }

    /// Decrypts into an owned buffer for `CaptureProtectedImageView` (digest re-verified; a mismatch deletes the file).
    func openAttachment(peer: String, messageId: String) throws -> OwnedPlaintextBuffer {
        let doc: ConversationDocument = loadConversation(peer)
        guard let i = doc.index(id: messageId, author: .peer) ?? doc.index(id: messageId, author: .me),
              let att = doc.messages[i].att else { throw AttachmentError.notDownloaded }
        return try AttachmentDownloader.open(att: att, blobs: blobs)
    }
}
