import Foundation
import OSLog

// MARK: - Inbound pipeline (§3.2b) on top of `Inbound.process`

/// What applying a stored inner message changed besides the document itself.
struct InnerEffects: Equatable {
    var timer: UInt32? = nil
    var contentFromPeer: Bool = false
    var imageMessageId: String? = nil
    var deletedBlobs: [String] = []

    init() {}
}

extension MessageSync {
    /// Runs one envelope through the policy and persists the outcome in the normative order: `conv/<peer>.json`
    /// (plaintext + outer id), then `sessions/<peer>.json` (advanced ratchet), then `index.json` (cursor +
    /// `pendingAcks` + everything else), then the Keychain generation. Returns false when nothing was persisted
    /// (the row may be redelivered: step 0 makes that deterministic). `serverId == nil` for a parked re-run.
    func processEnvelope(from peer: String, msgId: String, envelope: Data, serverId: Int64?, reprocessing: Bool) async -> Bool {
        let now: UInt64 = clock.now
        if let c = store.index.contact(peer), c.blocked {
            // "Engelle": dropped locally; acked so the server row does not stay queued (deviation, see report).
            do {
                try store.commitIndex { idx in idx.ledger.record(serverId: serverId ?? 0, acks: [msgId]) }
                return true
            } catch {
                return false
            }
        }
        var sessionDoc: SessionDocument
        do {
            sessionDoc = try sessions.load(peer: peer)
        } catch {
            MessageSync.logger.error("session load failed: \(String(describing: error), privacy: .public)")
            return false
        }
        var convDoc: ConversationDocument = loadConversation(peer)
        var original: ParkedEnvelope? = nil
        if reprocessing { original = convDoc.state.unpark(msgId: msgId) }
        let contact: ContactRecord? = store.index.contact(peer)
        let parsedOuter: ParsedEnvelope? = try? EnvelopeParser.parse(envelope)
        var lookup: LookupResult? = nil
        if contact == nil, let p = parsedOuter, p.outer.kind == .prekey {
            lookup = await lookupIdentity(peer)
        }
        let input: InboundInput = InboundInput(
            from: peer, msgId: msgId, envelope: envelope, now: now, local: local, localUsername: username,
            contact: contact, sessions: sessionDoc.peer, conversation: convDoc.state,
            prekeys: store.index.prekeys.lookup(), lookup: lookup, keySource: keySource)
        let result: InboundResult = Inbound.process(input)
        let sessionsChanged: Bool = result.sessions != sessionDoc.peer
        sessionDoc.peer = result.sessions
        convDoc.state = result.conversation
        if let o = original, case .parked = result.outcome, let i = convDoc.state.parked.firstIndex(where: { $0.msgId == msgId }) {
            // A re-run that parks again keeps the original lifetime.
            let p: ParkedEnvelope = convDoc.state.parked[i]
            convDoc.state.parked[i] = ParkedEnvelope(msgId: p.msgId, kind: p.kind, sid: p.sid, envelope: p.envelope,
                                                     receivedAt: o.receivedAt, reason: p.reason)
        }
        let acks: [String] = result.ackIds
        var opkUsed: [UInt32] = []
        var keyChange: Bool = false
        var overflowed: [String] = []
        for a in result.actions {
            switch a {
            case .deleteOneTimePrekey(let id): opkUsed.append(id)
            case .keyChangeDetected: keyChange = true
            case .ack(let id, .parkedOverflow) where id != msgId: overflowed.append(id)
            case .ack, .initiateRecovery, .rerunParked, .lookupIdentity, .contactCreated, .resyncReceived: break
            }
        }
        var effects: InnerEffects = InnerEffects()
        var undecryptable: String? = nil
        var writeConv: Bool = true
        switch result.outcome {
        case .stored(let inner, let sid):
            effects = applyInner(inner, sid: sid, peer: peer, now: now, conv: &convDoc)
        case .duplicate, .parked:
            break
        case .classified(let reason):
            undecryptable = reason.rawValue
            convDoc.append(MessageSync.systemRow(id: msgId, peer: peer, kind: .undecryptable, ts: now, now: now,
                                                 state: .undecryptable(reason.rawValue)))
        case .alreadyProcessed:
            writeConv = reprocessing
        }
        // A parked envelope evicted by this park was classified `parked_overflow`: it gets its row too.
        for id in overflowed {
            convDoc.append(MessageSync.systemRow(id: id, peer: peer, kind: .undecryptable, ts: now, now: now,
                                                 state: .undecryptable(InboundReason.parkedOverflow.rawValue)))
        }
        if !overflowed.isEmpty { writeConv = true }
        let evicted: [String] = overflowed
        let pendingIdentity: IdentityPublicKeys? = keyChange ? parsedOuter?.outer.x3dh?.identity : nil
        let stored: Bool
        if case .stored = result.outcome { stored = true } else { stored = false }
        let newContact: ContactRecord? = result.contact
        let applied: InnerEffects = effects
        let undecryptableReason: String? = undecryptable
        do {
            var writes: [DocumentWrite] = []
            if writeConv { writes.append(try DocumentWrite(path: LocalStore.conversationPath(peer), value: convDoc)) }
            if sessionsChanged { writes.append(try sessions.write(peer: peer, sessionDoc)) }
            try store.commit(writes) { idx in
                idx.ledger.record(serverId: serverId ?? 0, acks: acks)
                if let c = newContact { idx.upsertContact(c) }
                for id in opkUsed { idx.prekeys.markUsed(opkId: id) }
                let i: Int = idx.conversationIndex(peer, now: now)
                if stored {
                    idx.conversations[i].lastActivityAt = now
                    if applied.contentFromPeer { idx.conversations[i].unreadCount += 1 }
                    if let t = applied.timer { idx.conversations[i].timer = t }
                }
                if let p = pendingIdentity { idx.conversations[i].pendingKeyChange = p }
                if let r = undecryptableReason { idx.logUndecryptable(peer: peer, msgId: msgId, reason: r, at: now) }
                for id in evicted {
                    idx.logUndecryptable(peer: peer, msgId: id, reason: InboundReason.parkedOverflow.rawValue, at: now)
                }
            }
        } catch {
            MessageSync.logger.error("inbound persist failed: \(String(describing: error), privacy: .public)")
            return false
        }
        for blob in effects.deletedBlobs { blobs.delete(id: blob) }
        if writeConv { emit(.conversationChanged(peer: peer)) }
        await runPostCommitActions(result.actions, peer: peer, effects: effects)
        return true
    }

    func runPostCommitActions(_ actions: [InboundAction], peer: String, effects: InnerEffects) async {
        if let id = effects.imageMessageId {
            Task { [weak self] in
                await self?.downloadAttachment(peer: peer, messageId: id)
            }
        }
        for a in actions {
            switch a {
            case .ack, .deleteOneTimePrekey:
                break
            case .keyChangeDetected:
                emit(.keyChangeDetected(peer: peer))
            case .contactCreated:
                emit(.contactsChanged)
            case .lookupIdentity:
                scheduleLookupRetry(peer: peer)
            case .rerunParked(let sid):
                await rerunParked(peer: peer) { $0.sid == sid }
            case .initiateRecovery(let lostSid, _):
                await initiateRecovery(peer: peer, lostSid: lostSid)
            case .resyncReceived(let lostSid, _):
                await resendAfterResync(peer: peer, lostSid: lostSid)
            }
        }
    }

    static func systemRow(id: String, peer: String, kind: MessageKind, ts: UInt64, now: UInt64, state: MessageState,
                          author: MessageAuthor = .peer, timer: UInt32? = nil, capture: CaptureEvent? = nil) -> Message {
        var m: Message = Message(id: id, conversationID: peer, author: author, kind: kind, ts: ts, ttl: 0, state: state,
                                 timer: timer, capture: capture)
        m.receivedAt = now
        return m
    }

    /// Applies a decrypted inner message to the conversation document (§3.4 semantics).
    func applyInner(_ inner: InnerMessage, sid: Data, peer: String, now: UInt64, conv: inout ConversationDocument) -> InnerEffects {
        var effects: InnerEffects = InnerEffects()
        switch inner.t {
        case InnerMessageType.text:
            var m: Message = Message(id: inner.id, conversationID: peer, author: .peer, kind: .text, ts: inner.ts,
                                     ttl: inner.ttl, state: .received, text: inner.text ?? "", sentOnSid: sid)
            m.markReceived(at: now)
            conv.append(m)
            effects.contentFromPeer = true
        case InnerMessageType.image:
            guard let att = inner.att else { break }
            var m: Message = Message(id: inner.id, conversationID: peer, author: .peer, kind: .image, ts: inner.ts,
                                     ttl: inner.ttl, state: .received, att: att, sentOnSid: sid)
            m.markReceived(at: now)
            conv.append(m)
            effects.contentFromPeer = true
            effects.imageMessageId = inner.id
        case InnerMessageType.ctrlTimer:
            let t: UInt32 = inner.timer ?? 0
            effects.timer = t
            conv.append(MessageSync.systemRow(id: inner.id, peer: peer, kind: .timer, ts: inner.ts, now: now, state: .received, timer: t))
        case InnerMessageType.ctrlCapture:
            let event: CaptureEvent = CaptureEvent(peer: peer, seq: inner.seqTo, kind: inner.kind ?? "", ts: inner.ts,
                                                   ref: inner.ref ?? [], seqFrom: inner.seqFrom, seqTo: inner.seqTo, count: inner.count)
            if let to = inner.seqTo { conv.lastPeerCaptureSeq = max(conv.lastPeerCaptureSeq ?? 0, to) }
            conv.append(MessageSync.systemRow(id: inner.id, peer: peer, kind: .capture, ts: inner.ts, now: now, state: .received, capture: event))
        case InnerMessageType.ctrlRead:
            conv.applyRead(ids: inner.ref ?? [])
        case InnerMessageType.ctrlDelete:
            // Only ids authored by the sender of the control (the peer) are honoured; others are ignored and logged.
            let ids: [String] = inner.ref ?? []
            let removed: [Message] = conv.remove(ids: ids, author: .peer)
            effects.deletedBlobs = removed.compactMap { $0.att?.blob }
            if removed.count != ids.count {
                MessageSync.logger.notice("ctrl.delete ignored \(ids.count - removed.count, privacy: .public) foreign id(s)")
            }
        case InnerMessageType.ctrlResync:
            conv.append(MessageSync.systemRow(id: inner.id, peer: peer, kind: .resync, ts: inner.ts, now: now, state: .received))
        default:
            MessageSync.logger.notice("unknown inner type \(inner.t, privacy: .public)")
        }
        return effects
    }

    // MARK: identity lookup (§3.2 step 1)

    /// `GET /v1/users/{from}`: `200` with a valid binding → `.ok`, `404` → `.notFound`, a bad binding →
    /// `.mismatch`, anything transient → `.transient` (parks with `lookup_deferred`).
    func lookupIdentity(_ peer: String) async -> LookupResult {
        do {
            let user: UserResponse = try await api.lookup(username: peer)
            try user.verifyBinding()
            return .ok(user.identity)
        } catch let e as APIError {
            if e.status == 404 { return .notFound }
            if e.status == 401 { await reauthenticateIfNeeded() }
            return .transient
        } catch {
            return .mismatch
        }
    }

    func scheduleLookupRetry(peer: String) {
        guard lookupTasks[peer] == nil else { return }
        let attempt: Int = lookupRetries[peer] ?? 0
        let delays: [Double] = MessageSync.lookupRetryDelays
        let delay: Double = attempt < delays.count ? delays[attempt] : 3600
        lookupRetries[peer] = attempt + 1
        lookupTasks[peer] = Task { [weak self] in
            guard let self = self else { return }
            await self.retryLookup(peer: peer, delay: delay)
        }
    }

    func retryLookup(peer: String, delay: Double) async {
        do {
            try await sleeper.sleep(seconds: delay)
        } catch {
            lookupTasks[peer] = nil
            return
        }
        lookupTasks[peer] = nil
        await expireParked(peer: peer)
        await rerunParked(peer: peer) { $0.reason == .lookupDeferred }
        if loadConversation(peer).state.parked(reason: .lookupDeferred).isEmpty {
            lookupRetries[peer] = nil
        } else {
            scheduleLookupRetry(peer: peer)
        }
    }

    // MARK: parked envelopes (§3.2b step 2)

    /// Re-runs the pipeline for the parked envelopes of `peer` matching `predicate` (oldest first).
    func rerunParked(peer: String, where predicate: (ParkedEnvelope) -> Bool) async {
        let targets: [ParkedEnvelope] = loadConversation(peer).state.parked.filter(predicate)
        for p in targets {
            _ = await processEnvelope(from: peer, msgId: p.msgId, envelope: p.envelope, serverId: nil, reprocessing: true)
        }
    }

    /// Expired parked envelopes are classified with their expiry reason and acked (§3.2b step 5).
    func expireParked(peer: String) async {
        let now: UInt64 = clock.now
        var doc: ConversationDocument = loadConversation(peer)
        let expired: [(envelope: ParkedEnvelope, reason: InboundReason)] = doc.state.expireParked(now: now)
        guard !expired.isEmpty else { return }
        for e in expired {
            doc.append(MessageSync.systemRow(id: e.envelope.msgId, peer: peer, kind: .undecryptable, ts: now, now: now,
                                             state: .undecryptable(e.reason.rawValue)))
        }
        let acks: [String] = expired.map { $0.envelope.msgId }
        do {
            try store.commit([try DocumentWrite(path: LocalStore.conversationPath(peer), value: doc)]) { idx in
                idx.ledger.record(serverId: 0, acks: acks)
                for e in expired { idx.logUndecryptable(peer: peer, msgId: e.envelope.msgId, reason: e.reason.rawValue, at: now) }
            }
            emit(.conversationChanged(peer: peer))
        } catch {
            MessageSync.logger.error("parked expiry write failed: \(String(describing: error), privacy: .public)")
        }
    }

    func expireAllParked() async {
        for c in store.index.conversations {
            await expireParked(peer: c.peer)
        }
    }

    // MARK: key change (§3.2 step 1, S2)

    /// "Yeni anahtarı kabul et": replaces the record, supersedes old-identity sessions, resets `wm_secrets`,
    /// re-runs the parked `key_change` envelopes.
    func acceptKeyChange(peer: String) async throws {
        guard let pending = store.index.conversation(peer)?.pendingKeyChange else { return }
        var doc: SessionDocument = try sessions.load(peer: peer)
        doc.peer.applyS2(newPeerIdentity: pending)
        var contact: ContactRecord = store.index.contact(peer) ?? ContactRecord(username: peer, identity: pending, accepted: true)
        contact.acceptKeyChange(pending)
        contact.verified = false
        let record: ContactRecord = contact
        let now: UInt64 = clock.now
        try store.commit([try sessions.write(peer: peer, doc)]) { idx in
            idx.upsertContact(record)
            let i: Int = idx.conversationIndex(peer, now: now)
            idx.conversations[i].pendingKeyChange = nil
        }
        emit(.contactsChanged)
        await rerunParked(peer: peer) { $0.reason == .keyChange }
        await pumpOutbox()
    }

    // MARK: recovery (§3.2 S3 and the rejected-initiation path)

    /// Fetches a bundle and initiates a session; with `lostSid` its first inner message is `ctrl.resync`.
    func initiateSession(peer: String, lostSid: Data?) async throws -> SessionDocument {
        let now: UInt64 = clock.now
        let response: BundleResponse = try await api.fetchBundle(username: peer)
        let bundle: PrekeyBundle = response.bundle
        if let c = store.index.contact(peer), c.identity != bundle.identity {
            // Key change detected on fetch: banner, no session until acceptance.
            try store.commitIndex { idx in
                let i: Int = idx.conversationIndex(peer, now: now)
                idx.conversations[i].pendingKeyChange = bundle.identity
            }
            emit(.keyChangeDetected(peer: peer))
            throw SyncError.keyChangePending(peer: peer)
        }
        let session: Session = try SessionOutbound.initiate(bundle: bundle, local: local, localUsername: username,
                                                            now: now, keySource: keySource)
        var doc: SessionDocument = try sessions.load(peer: peer)
        doc.peer.addSession(session)
        var contact: ContactRecord = store.index.contact(peer) ?? ContactRecord(username: peer, identity: bundle.identity, accepted: true)
        contact.appendWMSecret(sid: session.sid, ws: session.ws)
        var item: OutboxItem? = nil
        if let lost = lostSid {
            let inner: InnerMessage = InnerMessage.resync(id: Identifiers.messageId(), ts: now, lostSid: lost)
            let msgId: String = Identifiers.hex32()
            _ = try SessionStore.encrypt(doc: &doc, on: session.sid, peer: peer, inner: inner, msgId: msgId, local: local, now: now)
            item = OutboxItem(id: msgId, payload: .envelope(to: peer, msgId: msgId, innerId: inner.id), priority: 0, createdAt: now)
        }
        let record: ContactRecord = contact
        try store.commit([try sessions.write(peer: peer, doc)]) { idx in
            idx.upsertContact(record)
            if let o = item { idx.outbox.append(o) }
            _ = idx.conversationIndex(peer, now: now)
        }
        return doc
    }

    func initiateRecovery(peer: String, lostSid: Data) async {
        do {
            _ = try await initiateSession(peer: peer, lostSid: lostSid)
            await pumpOutbox()
        } catch {
            MessageSync.logger.error("recovery initiation failed: \(String(describing: error), privacy: .public)")
        }
    }

    /// Sessions lost to rollback or parse failure at load time (S3): one recovery per lost sid.
    func recoverLostSessions() async {
        for c in store.index.conversations {
            do {
                _ = try sessions.load(peer: c.peer)
            } catch {
                continue
            }
            guard let lost = sessions.takePendingRecovery(peer: c.peer) else { continue }
            if lost.isEmpty {
                // Unparseable file: the lost sids are unknown, so a plain fresh initiation (S1 on the peer).
                do {
                    _ = try await initiateSession(peer: c.peer, lostSid: nil)
                } catch {
                    MessageSync.logger.error("re-initiation failed: \(String(describing: error), privacy: .public)")
                }
            }
            for sid in lost {
                await initiateRecovery(peer: c.peer, lostSid: sid)
            }
        }
    }

    /// `ctrl.resync` receiver: re-sends own messages sent on `lostSid` within 7 days (oldest first, ≤ 50) with
    /// their original `id`/`ts`/`ttl`, each a fresh ratchet encryption on the current sending session.
    func resendAfterResync(peer: String, lostSid: Data) async {
        let now: UInt64 = clock.now
        let doc: ConversationDocument = loadConversation(peer)
        let candidates: [OwnSentMessage] = SessionOutbound.resendCandidates(sent: doc.sent, lostSid: lostSid, now: now)
        for c in candidates {
            guard let i = doc.index(id: c.id, author: .me) else { continue }
            let m: Message = doc.messages[i]
            let inner: InnerMessage
            switch m.kind {
            case .text:
                inner = InnerMessage.text(id: m.id, ts: m.ts, ttl: m.ttl, text: m.text ?? "")
            case .image:
                guard let att = m.att else { continue }
                inner = InnerMessage(t: InnerMessageType.image, id: m.id, ts: m.ts, ttl: m.ttl, att: att)
            case .timer, .capture, .undecryptable, .resync, .keyChange:
                continue
            }
            do {
                _ = try await enqueueContent(peer: peer, inner: inner, newRow: false)
            } catch {
                MessageSync.logger.error("resend failed: \(String(describing: error), privacy: .public)")
                return
            }
        }
    }
}
