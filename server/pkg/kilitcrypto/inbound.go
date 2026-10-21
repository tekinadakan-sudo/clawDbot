package kilitcrypto

import "errors"

// Inbound processing policy of §3.2b with the responder rules of §3.2. The
// pipeline is a pure function of (device state, envelope, now): it mutates
// the device and returns the ordered list of actions it took, so the Swift
// port and the vector generator can assert every step.

// Undecryptable reason codes (§3.2b step 4).
const (
	ReasonBadEnvelope      = "bad_envelope"
	ReasonUnknownSID       = "unknown_sid"
	ReasonIdentityMismatch = "identity_mismatch"
	ReasonLookupFailed     = "lookup_failed"
	ReasonKeyChangeExpired = "key_change_expired"
	ReasonParkedOverflow   = "parked_overflow"
	ReasonReplay           = "replay"
	ReasonOPKGone          = "opk_gone"
	ReasonSPKGone          = "spk_gone"
	ReasonTooManySkipped   = "too_many_skipped"
	ReasonDecryptFailed    = "decrypt_failed"
)

// Parking reasons (§3.2b step 2).
const (
	ParkKeyChange      = "key_change"
	ParkUnknownSID     = "unknown_sid"
	ParkLookupDeferred = "lookup_deferred"
)

// decrypted is a successful RatchetDecrypt that has not been committed yet.
type decrypted struct {
	sess  *Session
	state *State // advanced ratchet state
	inner *Inner
	// fresh initiation only:
	fresh bool
	ek    []byte
	opkID *uint32
}

// Inbound runs one fetched envelope through the pipeline.
func (d *Device) Inbound(in Inbound, now int64) []Action {
	if in.From == d.Identity.Username || in.From == "" {
		return []Action{{Kind: ActIgnored, Peer: in.From, MsgID: in.MsgID, Reason: "bad_sender"}}
	}
	p := d.peer(in.From)
	// Step 0: outer dedupe before any KDF.
	if p.isProcessed(in.MsgID, now) {
		return []Action{{Kind: ActAlreadyProcessed, Peer: in.From, MsgID: in.MsgID}, d.ack(in)}
	}
	if p.parkedIndex(in.MsgID) >= 0 {
		// The same row delivered by both WS and poll while parked: never ack while parked.
		return []Action{{Kind: ActIgnored, Peer: in.From, MsgID: in.MsgID, Reason: "parked"}}
	}
	return d.process(p, in, nil, now)
}

// process is steps 1–5 for a new or re-run (prev != nil) envelope.
func (d *Device) process(p *Peer, in Inbound, prev *Parked, now int64) []Action {
	env, err := ParseEnvelope(in.Envelope)
	if err != nil {
		return d.classify(p, in, ReasonBadEnvelope, now)
	}
	if env.Kind == KindPrekey {
		return d.processPrekey(p, in, env, prev, now)
	}
	return d.processMsg(p, in, env, prev, now)
}

// processPrekey is §3.2 responder rules 1–3.
func (d *Device) processPrekey(p *Peer, in Inbound, env *Envelope, prev *Parked, now int64) []Action {
	x := env.X3DH
	claimed := PeerIdentity{Username: in.From, IKSig: dup(x.IKSig), IKDH: dup(x.IKDH)}
	// Step 1: identity binding.
	if err := VerifyIdentityBinding(x.IKSig, x.IKDH, x.IKBindSig); err != nil {
		return d.classify(p, in, ReasonBadEnvelope, now)
	}
	var acts []Action
	if p.Contact != nil {
		if !sameIdentity(p.Contact.Identity, claimed) {
			p.Contact.KeyChange = &claimed
			acts = append(acts, Action{Kind: ActKeyChange, Peer: p.Username, MsgID: in.MsgID})
			return append(acts, d.park(p, in, env, ParkKeyChange, prev, now)...)
		}
	} else {
		res := d.lookup(p.Username)
		switch res.Status {
		case LookupOK:
			if res.Identity == nil || !sameIdentity(*res.Identity, claimed) {
				return d.classify(p, in, ReasonIdentityMismatch, now)
			}
			p.Contact = &Contact{Identity: claimed}
			acts = append(acts, Action{Kind: ActMessageRequest, Peer: p.Username, MsgID: in.MsgID})
		case LookupNotFound:
			return d.classify(p, in, ReasonIdentityMismatch, now)
		default:
			return append(acts, d.park(p, in, env, ParkLookupDeferred, prev, now)...)
		}
	}
	// Step 2: routing to an existing session, then replay exclusion.
	if s := p.session(env.SID); s != nil {
		return append(acts, d.decryptOn(p, s, in, env, now)...)
	}
	if p.seenEK(x.EK, now) {
		return append(acts, d.classify(p, in, ReasonReplay, now)...)
	}
	// Step 3: fresh initiation.
	spk := d.spk(x.SPKID, now)
	if spk == nil {
		return append(acts, d.rejected(p, in, env, ReasonSPKGone, now)...)
	}
	var opkPriv []byte
	if x.OPKID != nil {
		o := d.opk(*x.OPKID, now)
		if o == nil {
			return append(acts, d.rejected(p, in, env, ReasonOPKGone, now)...)
		}
		opkPriv = o.Priv
	}
	keys, err := Respond(d.Identity, claimed, x.IKBindSig, x.EK, spk.Priv, opkPriv)
	if err != nil {
		return append(acts, d.classify(p, in, ReasonDecryptFailed, now)...)
	}
	rec := &recordingKS{inner: d.ks}
	cand, err := InitBob(keys.SK, spk.Priv, rec)
	if err != nil {
		return append(acts, d.classify(p, in, ReasonDecryptFailed, now)...)
	}
	inner, err := d.tryDecrypt(cand, env, keys.AD, keys.SID, now)
	if err != nil {
		// A candidate state never consumes a key (§3.8); an AEAD failure on a
		// fresh initiation is a forgery or a replay and never recovers (§3.2).
		d.ks.pushBack(rec.drawn)
		cand.Zeroize()
		return append(acts, d.classify(p, in, decryptReason(err), now)...)
	}
	cand.KS = d.ks
	sess := &Session{
		SID: keys.SID, Role: RoleResponder, CreatedAt: now, WS: keys.WS, AD: keys.AD,
		Local: d.LocalIdentity(), Peer: claimed,
	}
	keys.DH1, keys.DH2, keys.DH3, keys.DH4 = nil, nil, nil, nil
	return append(acts, d.commit(p, in, decrypted{sess: sess, state: cand, inner: inner, fresh: true, ek: x.EK, opkID: x.OPKID}, now)...)
}

// processMsg routes a msg envelope by sid (§3.2b step 2).
func (d *Device) processMsg(p *Peer, in Inbound, env *Envelope, prev *Parked, now int64) []Action {
	s := p.session(env.SID)
	if s == nil {
		acts := d.park(p, in, env, ParkUnknownSID, prev, now)
		if k := p.knownSID(env.SID, now); k != nil &&
			(k.DeletedReason == DeletedRollback || k.DeletedReason == DeletedParseFailure) &&
			p.recoveryAllowed(now) {
			acts = append(acts, d.initiateResync(p, env.SID, now)...)
		}
		return acts
	}
	return d.decryptOn(p, s, in, env, now)
}

// decryptOn runs RatchetDecrypt on a copy of the selected session's state.
func (d *Device) decryptOn(p *Peer, s *Session, in Inbound, env *Envelope, now int64) []Action {
	rec := &recordingKS{inner: d.ks}
	cand := s.Ratchet.Clone()
	cand.KS = rec
	inner, err := d.tryDecrypt(cand, env, s.AD, s.SID, now)
	if err != nil {
		d.ks.pushBack(rec.drawn)
		cand.Zeroize()
		return d.classify(p, in, decryptReason(err), now)
	}
	cand.KS = d.ks
	return d.commit(p, in, decrypted{sess: s, state: cand, inner: inner}, now)
}

// tryDecrypt is RatchetDecrypt + Unpad + DecodeInner on st.
func (d *Device) tryDecrypt(st *State, env *Envelope, ad []byte, sid [8]byte, now int64) (*Inner, error) {
	pt, err := st.Decrypt(env.Header, env.Ct, ad, sid, now)
	if err != nil {
		return nil, err
	}
	raw, err := Unpad(pt)
	if err != nil {
		return nil, err
	}
	return DecodeInner(raw)
}

func decryptReason(err error) string {
	if errors.Is(err, ErrTooManySkipped) {
		return ReasonTooManySkipped
	}
	return ReasonDecryptFailed
}

// commit is §3.2b step 3 in its normative order: (a) conversation write,
// (b) session commit, (c) cursor + pendingAcks, (d) ack; then the control
// side effects and parked re-runs.
func (d *Device) commit(p *Peer, in Inbound, dec decrypted, now int64) []Action {
	var acts []Action
	m := dec.inner
	dupe := p.isDuplicate(AuthorPeer, m.ID, now)
	// (a) conv/<peer>.json: plaintext row (or silent drop), dedupe entry, processed msg_id.
	if !dupe {
		p.addDedupe(AuthorPeer, m.ID, now)
		acts = append(acts, d.applyInner(p, in, m, now)...)
	}
	p.addProcessed(in.MsgID, now)
	if d.CrashAfter == CrashAfterConv {
		d.CrashAfter = CrashNone
		return append(acts, Action{Kind: ActCrashed, Peer: p.Username, MsgID: in.MsgID, Reason: "after_conv"})
	}
	// (b) sessions/<peer>.json: the advanced state, the new session, seen_ek, OPK deletion, S1.
	s := dec.sess
	if dec.fresh {
		acts = append(acts, d.addSession(p, s, now)...)
		p.addSeenEK(dec.ek, now)
		if dec.opkID != nil {
			for i := range d.OPKs {
				if d.OPKs[i].ID == *dec.opkID {
					acts = append(acts, Action{Kind: ActKeyDeleted, Reason: "opk", KeyID: *dec.opkID})
					d.removeOPK(i)
					break
				}
			}
		}
		for _, o := range p.Sessions {
			if o != s && !o.Superseded && o.HasActivity() {
				o.Superseded, o.SupersededReason = true, SupersededS1
				acts = append(acts, Action{Kind: ActSuperseded, Peer: p.Username, SID: o.SID, Reason: SupersededS1})
			}
		}
	}
	if s.Ratchet != nil && s.Ratchet != dec.state {
		s.Ratchet.Zeroize()
	}
	s.Ratchet = dec.state
	s.LastActivity = now
	s.PendingX3DH = nil
	if d.CrashAfter == CrashAfterSession {
		d.CrashAfter = CrashNone
		return append(acts, Action{Kind: ActCrashed, Peer: p.Username, MsgID: in.MsgID, Reason: "after_session"})
	}
	// (c) + (d): cursor already advanced; the ack joins pendingAcks.
	if dupe {
		acts = append(acts, Action{Kind: ActDuplicate, Peer: p.Username, MsgID: in.MsgID, SID: s.SID, InnerID: m.ID, T: m.T})
	} else {
		acts = append(acts, Action{Kind: ActStored, Peer: p.Username, MsgID: in.MsgID, SID: s.SID, InnerID: m.ID, T: m.T})
	}
	acts = append(acts, d.ack(in))
	// ctrl.resync: supersede lost_sid even without lastActivity, then re-send.
	if !dupe && m.T == TResync {
		acts = append(acts, d.applyResync(p, m, now)...)
	}
	if dec.fresh {
		acts = append(acts, d.rerunParked(p, ParkUnknownSID, &s.SID, now)...)
	}
	return acts
}

// applyInner records a text/image row or applies a control message to the
// conversation document.
func (d *Device) applyInner(p *Peer, in Inbound, m *Inner, now int64) []Action {
	switch m.T {
	case TText, TImage:
		row := &Message{Author: AuthorPeer, ID: m.ID, T: m.T, Ts: m.Ts, Ttl: m.Ttl, Att: m.Att, ReceivedAt: now, MsgID: in.MsgID}
		if m.Text != nil {
			row.Text = *m.Text
		}
		p.Messages = append(p.Messages, row)
		return nil
	case TDelete:
		// ref entries name messages authored by the sender of the control.
		kept := p.Messages[:0]
		for _, row := range p.Messages {
			if row.Author == AuthorPeer && contains(m.Ref, row.ID) {
				continue
			}
			kept = append(kept, row)
		}
		p.Messages = kept
	case TRead:
		// only ids authored by the recipient of the receipt (the local user)
		for _, row := range p.Messages {
			if row.Author == AuthorMe && contains(m.Ref, row.ID) {
				row.Read = true
			}
		}
	case TTimer:
		if m.Timer != nil {
			p.Timer = *m.Timer
		}
	case TCapture:
		if m.SeqTo != nil && *m.SeqTo > p.LastPeerCaptureSeq {
			p.LastPeerCaptureSeq = *m.SeqTo
		}
	}
	return []Action{{Kind: ActControl, Peer: p.Username, MsgID: in.MsgID, InnerID: m.ID, T: m.T}}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// applyResync is the receiver side of ctrl.resync (§3.4).
func (d *Device) applyResync(p *Peer, m *Inner, now int64) []Action {
	if m.LostSid == nil {
		return nil
	}
	raw, err := Base64urlDecode(*m.LostSid)
	if err != nil || len(raw) != 8 {
		return nil
	}
	var lost [8]byte
	copy(lost[:], raw)
	var acts []Action
	if s := p.session(lost); s != nil && !s.Superseded {
		s.Superseded, s.SupersededReason = true, SupersededResync
		acts = append(acts, Action{Kind: ActSuperseded, Peer: p.Username, SID: lost, Reason: SupersededResync})
	}
	set := d.ResyncResendSet(p.Username, lost, now)
	if len(set) == 0 {
		return acts
	}
	target := d.SendingSession(p.Username)
	if target == nil {
		var err error
		var more []Action
		target, more, err = d.initiateSession(p, now)
		acts = append(acts, more...)
		if err != nil {
			return acts
		}
	}
	for _, row := range set {
		inner := &Inner{T: row.T, ID: row.ID, Ts: row.Ts, Ttl: row.Ttl, Att: row.Att}
		if row.T == TText {
			t := row.Text
			inner.Text = &t
		}
		out, err := d.sendOn(p, target, inner, now, true)
		if err != nil {
			acts = append(acts, Action{Kind: ActInitiateFailed, Peer: p.Username, Err: err})
			break
		}
		acts = append(acts, Action{Kind: ActResend, Peer: p.Username, SID: target.SID, InnerID: row.ID, T: row.T, Outbound: out})
	}
	return acts
}

// rejected is the spk_gone / opk_gone classification with the
// rejected-initiation recovery path of §3.2 step 3.
func (d *Device) rejected(p *Peer, in Inbound, env *Envelope, reason string, now int64) []Action {
	acts := d.classify(p, in, reason, now)
	if p.Contact == nil || !p.Contact.Accepted {
		return acts // pending message request: classified only
	}
	if p.knownSID(env.SID, now) != nil || !p.recoveryAllowed(now) {
		return acts
	}
	p.KnownSIDs = append(p.KnownSIDs, KnownSID{SID: env.SID, DeletedReason: DeletedRejectedInitiation, DeletedAt: now})
	return append(acts, d.initiateResync(p, env.SID, now)...)
}

// classify is §3.2b step 4: a system row, the processed id and the ack.
func (d *Device) classify(p *Peer, in Inbound, reason string, now int64) []Action {
	p.Undecryptable = append(p.Undecryptable, Undecryptable{MsgID: in.MsgID, Reason: reason, At: now})
	p.addProcessed(in.MsgID, now)
	return []Action{{Kind: ActClassified, Peer: p.Username, MsgID: in.MsgID, Reason: reason}, d.ack(in)}
}

// park stores an envelope that cannot be processed yet (§3.2b step 2). prev
// is the entry being re-run, whose receivedAt and attempts are preserved.
func (d *Device) park(p *Peer, in Inbound, env *Envelope, reason string, prev *Parked, now int64) []Action {
	e := Parked{MsgID: in.MsgID, ServerID: in.ServerID, Kind: env.Kind, SID: env.SID, From: in.From, Envelope: in.Envelope, ReceivedAt: now, Reason: reason}
	if prev != nil {
		e.ReceivedAt, e.Attempts = prev.ReceivedAt, prev.Attempts
		if reason == ParkLookupDeferred && prev.Reason == ParkLookupDeferred {
			e.Attempts++
		}
	}
	if reason == ParkLookupDeferred {
		delay := LookupRetryDelays[len(LookupRetryDelays)-1]
		if e.Attempts < len(LookupRetryDelays) {
			delay = LookupRetryDelays[e.Attempts]
		}
		e.NextRetryAt = now + delay
	}
	var acts []Action
	if prev == nil && len(p.Parked) >= ParkedMax {
		oldest := p.Parked[0]
		p.Parked = p.Parked[1:]
		acts = append(acts, d.classify(p, oldest.inbound(), ReasonParkedOverflow, now)...)
	}
	p.Parked = append(p.Parked, e)
	d.advanceCursor(in.ServerID) // parked envelopes are already on the device
	return append(acts, Action{Kind: ActParked, Peer: p.Username, MsgID: in.MsgID, Reason: reason, SID: env.SID})
}

// rerunParked re-runs the parked envelopes of p with the given reason (and,
// for unknown_sid, the given sid), or exactly the entry one when set.
func (d *Device) rerunParked(p *Peer, reason string, sid *[8]byte, now int64) []Action {
	var acts []Action
	ids := make([]string, 0, len(p.Parked))
	for _, e := range p.Parked {
		if reason != "" && e.Reason != reason {
			continue
		}
		if sid != nil && e.SID != *sid {
			continue
		}
		ids = append(ids, e.MsgID)
	}
	for _, id := range ids {
		i := p.parkedIndex(id)
		if i < 0 {
			continue
		}
		e := p.Parked[i]
		p.Parked = append(p.Parked[:i:i], p.Parked[i+1:]...)
		acts = append(acts, d.process(p, e.inbound(), &e, now)...)
	}
	return acts
}

// rerunParkedEntry re-runs one entry (lookup_deferred retries).
func (d *Device) rerunParkedEntry(p *Peer, e Parked, now int64) []Action {
	if i := p.parkedIndex(e.MsgID); i >= 0 {
		p.Parked = append(p.Parked[:i:i], p.Parked[i+1:]...)
	}
	return d.process(p, e.inbound(), &e, now)
}

// lookup answers a TOFU lookup from LookupOverride (once) or the Directory.
func (d *Device) lookup(peer string) LookupResult {
	if d.LookupOverride != nil {
		r := *d.LookupOverride
		d.LookupOverride = nil
		return r
	}
	if d.Directory == nil {
		return LookupResult{Status: LookupTransient}
	}
	return d.Directory.LookupUser(peer)
}
