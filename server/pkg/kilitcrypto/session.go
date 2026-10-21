package kilitcrypto

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
)

// This file models one device's per-peer protocol state exactly as the Swift
// app keeps it (§3.2, §3.2b, §5.3): contact records, sessions with the
// sending-session rule and supersession S1–S3, seen_ek, known_sids, parked
// envelopes, dedupe sets, pendingAcks and the cursor, plus the SPK/OPK
// private-key store with the §3.1 deletion rules. Every method takes the
// clock as a parameter and draws keys only from the injected KeySource, so a
// scripted run is fully deterministic (the WP1c vector generator scripts it).
// The inbound pipeline itself is in inbound.go.

// Lifetimes and bounds (§3.1, §3.2, §3.2b, §3.4).
const (
	SeenEKMaxAge        = 45 * 86400 // seen_ek entries
	SeenEKMax           = 64         // last 64 accepted ek values
	KnownSIDMaxAge      = 90 * 86400 // known_sids entries
	DedupeMaxAge        = 45 * 86400 // (author, id) dedupe window
	DedupeMax           = 10000      // (author, id) entries
	ProcessedMaxAge     = 30 * 86400 // processed_msg_ids window
	ProcessedMax        = 10000      // processed_msg_ids entries
	ParkedMax           = 100        // parked envelopes per peer
	ParkedKeyChangeTTL  = 7 * 86400  // key_change parking lifetime
	ParkedUnknownSIDTTL = 86400      // unknown_sid parking lifetime
	ParkedLookupTTL     = 86400      // lookup_deferred parking lifetime
	SPKPrivMaxAge       = 28 * 86400 // SPK private key deleted after this
	OPKGrace            = 7 * 86400  // OPK private key deleted this long after consumed_ids
	OPKMaxStored        = 500        // OPK private keys kept
	SessionsPerPeer     = 4          // beyond this the oldest superseded session is deleted
	SupersededMaxAge    = 30 * 86400 // superseded sessions deleted after lastActivity + this
	RecoveryInterval    = 600        // one recovery initiation per peer per 10 min
	ResendWindow        = 7 * 86400  // ctrl.resync resend set: own messages sent within this
	ResendMax           = 50         // ctrl.resync resend set bound (oldest first)
	PendingAcksMax      = 5000       // pendingAcks bound (oldest dropped)
)

// LookupRetryDelays is the lookup_deferred retry schedule of §3.2 step 1:
// 10 s, 1 m, 10 m, 1 h, then hourly.
var LookupRetryDelays = []int64{10, 60, 600, 3600}

// Role of a session (§3.2).
type Role string

const (
	RoleInitiator Role = "initiator"
	RoleResponder Role = "responder"
)

// known_sids deletedReason values (§3.2 S3).
const (
	DeletedRollback           = "rollback"
	DeletedParseFailure       = "parse_failure"
	DeletedRejectedInitiation = "rejected_initiation"
	DeletedPruned             = "pruned"
)

// Supersession reasons (§3.2 S1, S2 and ctrl.resync).
const (
	SupersededS1          = "s1"
	SupersededOldIdentity = "oldIdentity"
	SupersededResync      = "resync"
)

// Author of a conversation row.
type Author string

const (
	AuthorMe   Author = "me"
	AuthorPeer Author = "peer"
)

// Inner message types of §3.4.
const (
	TText    = "text"
	TImage   = "image"
	TTimer   = "ctrl.timer"
	TCapture = "ctrl.capture"
	TRead    = "ctrl.read"
	TDelete  = "ctrl.delete"
	TResync  = "ctrl.resync"
)

var (
	// ErrKeyChangePending is returned by Send while the "Güvenlik numarası
	// değişti" banner is up for the peer (§3.6): sending is disabled until
	// AcceptKeyChange.
	ErrKeyChangePending = errors.New("kilitcrypto: key change pending")
	// ErrOffline is a transient directory failure (offline, 5xx, 429,
	// timeout, 401 until re-login); it parks a TOFU lookup as lookup_deferred.
	ErrOffline = errors.New("kilitcrypto: server unreachable")
	// ErrUnknownUser is a definitive 404 from the directory.
	ErrUnknownUser = errors.New("kilitcrypto: unknown user")
)

// WMSecret is one entry of a contact's wm_secrets: the watermark secret of a
// session, kept after the session itself is gone so old screenshots stay
// attributable.
type WMSecret struct {
	SID [8]byte
	WS  []byte
}

// Contact is the per-peer record of index.json (§3.2 step 1, step 4).
type Contact struct {
	Identity PeerIdentity
	Verified bool // safety number compared by the user
	Accepted bool // "Kabul et" tapped, or the local user started the conversation
	// KeyChange holds the identity keys the peer now claims while the
	// blocking banner is shown; nil otherwise. AcceptKeyChange adopts it.
	KeyChange *PeerIdentity
	WMSecrets []WMSecret
}

// PendingX3DH is copied into every outgoing envelope of an initiator session
// until the first successful decrypt of a peer message on it (§3.2).
type PendingX3DH struct {
	EKPub []byte
	SPKID uint32
	OPKID *uint32
}

// Session is one Double Ratchet session with a peer (§3.2, §5.3).
type Session struct {
	SID              [8]byte
	Role             Role
	CreatedAt        int64
	LastActivity     int64 // unix seconds of the last successful decrypt of a peer message; 0 = none
	Superseded       bool  // sticky
	SupersededReason string
	WS               []byte
	AD               []byte
	Local            PeerIdentity // identity keys bound in AD
	Peer             PeerIdentity
	Ratchet          *State
	PendingX3DH      *PendingX3DH
}

// HasActivity reports whether a peer message has ever decrypted on the session.
func (s *Session) HasActivity() bool { return s.LastActivity != 0 }

// SeenEK is one seen_ek entry.
type SeenEK struct {
	EK     []byte
	SeenAt int64
}

// KnownSID is one known_sids entry: the sid of a session this device no
// longer has, with why it is gone (§3.2 S3 trigger bound).
type KnownSID struct {
	SID           [8]byte
	DeletedReason string
	DeletedAt     int64
}

// Parked is one parked envelope (§3.2b step 2).
type Parked struct {
	MsgID       string
	ServerID    uint64
	Kind        string
	SID         [8]byte
	From        string
	Envelope    []byte
	ReceivedAt  int64
	Reason      string // key_change | unknown_sid | lookup_deferred
	Attempts    int    // lookup_deferred retries so far
	NextRetryAt int64  // lookup_deferred only
}

// Message is a conversation row (text and image messages only; control
// messages are applied and recorded in the dedupe set but never shown).
type Message struct {
	Author     Author
	ID         string
	T          string
	Ts         int64
	Ttl        int
	Text       string
	Att        *Attach
	SentOnSID  [8]byte // own messages: the session they were last encrypted on
	SentAt     int64
	ReceivedAt int64
	MsgID      string // own: outer msg_id of the last send; peer: outer msg_id it arrived in
	Read       bool
}

// Undecryptable is the local system row "Bu mesaj çözülemedi (<reason>)".
type Undecryptable struct {
	MsgID  string
	Reason string
	At     int64
}

// DedupeEntry is one (author, id) entry.
type DedupeEntry struct {
	Author Author
	ID     string
	At     int64
}

// ProcessedID is one processed_msg_ids entry.
type ProcessedID struct {
	MsgID string
	At    int64
}

// Peer is everything the device keeps about one peer: index.json's contact
// record, sessions/<peer>.json and conv/<peer>.json.
type Peer struct {
	Username           string
	Contact            *Contact
	Sessions           []*Session
	SeenEK             []SeenEK
	KnownSIDs          []KnownSID
	Parked             []Parked
	ProcessedMsgIDs    []ProcessedID
	Dedupe             []DedupeEntry
	Messages           []*Message
	Undecryptable      []Undecryptable
	Timer              int
	LastPeerCaptureSeq uint64
	RecoveryAt         int64 // last recovery initiation (rejected initiation or S3); 0 = never
}

// SPKRecord is a stored signed-prekey private key (§3.1).
type SPKRecord struct {
	ID        uint32
	Priv      []byte
	CreatedAt int64
}

// OPKRecord is a stored one-time-prekey private key (§3.1).
type OPKRecord struct {
	ID                 uint32
	Priv               []byte
	UploadedAt         int64
	ConsumedReportedAt int64 // 0 = never reported
}

// LookupStatus is the outcome of GET /v1/users/{from} (§3.2 step 1).
type LookupStatus int

const (
	LookupOK        LookupStatus = iota // 200; Identity carries the served keys
	LookupNotFound                      // 404 → identity_mismatch
	LookupTransient                     // offline, 5xx, 429, timeout, 401 → lookup_deferred
)

// LookupResult is a directory answer.
type LookupResult struct {
	Status   LookupStatus
	Identity *PeerIdentity
}

// Directory is the server as the device sees it for session setup: bundle
// fetches (which claim an OPK) and identity lookups. Tests and the vector
// generator inject a scripted one.
type Directory interface {
	FetchBundle(peer string) (*Bundle, error)
	LookupUser(peer string) LookupResult
}

// Outbound is an envelope the device wants to POST /v1/messages.
type Outbound struct {
	To       string
	MsgID    string
	Envelope []byte
	SID      [8]byte
	Kind     string
	InnerID  string
	T        string
	Resend   bool
}

// Inbound is one delivered server row.
type Inbound struct {
	ServerID uint64
	MsgID    string
	From     string
	Envelope []byte
}

// ActionKind labels what the pipeline did.
type ActionKind string

const (
	ActStored           ActionKind = "stored"            // plaintext appended (step 3)
	ActDuplicate        ActionKind = "duplicate"         // (author, id) already present; acked silently
	ActAlreadyProcessed ActionKind = "already_processed" // outer msg_id known (step 0)
	ActParked           ActionKind = "parked"            // Reason = parking reason
	ActClassified       ActionKind = "classified"        // undecryptable, Reason = reason code
	ActAck              ActionKind = "ack"               // MsgID appended to pendingAcks
	ActInitiate         ActionKind = "initiate"          // new own session; Outbound is its first envelope
	ActInitiateFailed   ActionKind = "initiate_failed"   // bundle fetch or X3DH failed; Err set
	ActResend           ActionKind = "resend"            // ctrl.resync resend; Outbound set
	ActSuperseded       ActionKind = "superseded"        // Reason = s1 | oldIdentity | resync
	ActSessionDeleted   ActionKind = "session_deleted"   // Reason = deletedReason
	ActKeyChange        ActionKind = "key_change"        // banner shown for Peer
	ActMessageRequest   ActionKind = "message_request"   // contact created by TOFU, pending
	ActControl          ActionKind = "control"           // a control message was applied; T set
	ActCrashed          ActionKind = "crashed"           // CrashAfter hit
	ActIgnored          ActionKind = "ignored"           // duplicate delivery of a parked row, or own message
	ActKeyDeleted       ActionKind = "key_deleted"       // SPK/OPK private key deleted; Reason = spk | opk
)

// Action is one pipeline outcome.
type Action struct {
	Kind     ActionKind
	Peer     string
	MsgID    string
	Reason   string
	SID      [8]byte
	LostSID  *[8]byte
	InnerID  string
	T        string
	KeyID    uint32
	Outbound *Outbound
	Err      error
}

// CrashPoint injects a crash inside §3.2b step 3 so that redelivery can be
// tested: after (a) the conversation write, or after (b) the session commit.
type CrashPoint int

const (
	CrashNone CrashPoint = iota
	CrashAfterConv
	CrashAfterSession
)

// Device is one user's device.
type Device struct {
	Identity      Identity
	Directory     Directory
	SPKs          []SPKRecord
	OPKs          []OPKRecord
	RetiredOPKIDs map[uint32]bool // ids deleted by the 500 cap; never re-uploaded
	Peers         map[string]*Peer
	Cursor        uint64
	PendingAcks   []string
	Outbox        []Outbound
	CrashAfter    CrashPoint
	// LookupOverride, when set, answers the next TOFU lookup instead of
	// Directory (the lookup_result op of §3.9) and is then cleared.
	LookupOverride *LookupResult

	ks         *keyQueue
	msgCounter uint64
	idCounter  uint64
}

// NewDevice creates a device with no peers. ks supplies EK and DHs in the
// §3.8 order; dir is the server.
func NewDevice(id Identity, ks KeySource, dir Directory) *Device {
	return &Device{
		Identity:      id,
		Directory:     dir,
		RetiredOPKIDs: map[uint32]bool{},
		Peers:         map[string]*Peer{},
		ks:            &keyQueue{inner: ks},
	}
}

// keyQueue is the device's GENERATE_DH: keys handed back by a failed
// (uncommitted) decrypt are served again before the underlying source, so an
// uncommitted state never consumes a scripted key (§3.8).
type keyQueue struct {
	inner   KeySource
	pending [][]byte
}

func (q *keyQueue) X25519Private() ([]byte, error) {
	if len(q.pending) > 0 {
		k := q.pending[0]
		q.pending = q.pending[1:]
		return k, nil
	}
	return q.inner.X25519Private()
}

func (q *keyQueue) pushBack(keys [][]byte) {
	if len(keys) == 0 {
		return
	}
	q.pending = append(append([][]byte(nil), keys...), q.pending...)
}

// recordingKS remembers copies of every key drawn through it.
type recordingKS struct {
	inner KeySource
	drawn [][]byte
}

func (r *recordingKS) X25519Private() ([]byte, error) {
	k, err := r.inner.X25519Private()
	if err == nil {
		r.drawn = append(r.drawn, dup(k))
	}
	return k, err
}

// KeySource returns the device's GENERATE_DH (for direct ratchet calls).
func (d *Device) KeySource() KeySource { return d.ks }

// LocalIdentity is the device's own identity as a PeerIdentity.
func (d *Device) LocalIdentity() PeerIdentity {
	return PeerIdentity{Username: d.Identity.Username, IKSig: d.Identity.IKSigPub(), IKDH: d.Identity.IKDHPub()}
}

// NextMsgID returns a fresh outer msg_id (16 bytes, lowercase hex). It is
// derived from a per-device counter so scripted runs are reproducible.
func (d *Device) NextMsgID() string {
	d.msgCounter++
	h := SHA256([]byte("Kilit_msgid"), []byte(d.Identity.Username), U64BE(d.msgCounter))
	return HexString(h[:16])
}

// NextInnerID returns a fresh inner message id in UUID spelling.
func (d *Device) NextInnerID() string {
	d.idCounter++
	h := SHA256([]byte("Kilit_innerid"), []byte(d.Identity.Username), U64BE(d.idCounter))
	x := HexString(h[:16])
	return fmt.Sprintf("%s-%s-%s-%s-%s", x[0:8], x[8:12], x[12:16], x[16:20], x[20:32])
}

// ---- prekey store (§3.1) ----

// AddSPK stores a signed-prekey private key.
func (d *Device) AddSPK(id uint32, priv []byte, createdAt int64) {
	d.SPKs = append(d.SPKs, SPKRecord{ID: id, Priv: dup(priv), CreatedAt: createdAt})
}

// AddOPK stores a one-time-prekey private key uploaded at now. A retired id
// is ignored; beyond 500 keys the oldest by uploadedAt are deleted first.
func (d *Device) AddOPK(id uint32, priv []byte, now int64) {
	if d.RetiredOPKIDs[id] {
		return
	}
	for _, o := range d.OPKs {
		if o.ID == id {
			return
		}
	}
	d.OPKs = append(d.OPKs, OPKRecord{ID: id, Priv: dup(priv), UploadedAt: now})
	for len(d.OPKs) > OPKMaxStored {
		oldest := 0
		for i, o := range d.OPKs {
			if o.UploadedAt < d.OPKs[oldest].UploadedAt {
				oldest = i
			}
		}
		d.RetiredOPKIDs[d.OPKs[oldest].ID] = true
		d.removeOPK(oldest)
	}
}

func (d *Device) removeOPK(i int) {
	clear(d.OPKs[i].Priv)
	d.OPKs = append(d.OPKs[:i:i], d.OPKs[i+1:]...)
}

// ConsumedReport records a server consumed_ids report at now: it is purely a
// refill signal; the private key is deleted 7 days later (§3.1 rule (b)).
func (d *Device) ConsumedReport(ids []uint32, now int64) {
	for _, id := range ids {
		for i := range d.OPKs {
			if d.OPKs[i].ID == id && d.OPKs[i].ConsumedReportedAt == 0 {
				d.OPKs[i].ConsumedReportedAt = now
			}
		}
	}
}

// spk returns the stored SPK with id, applying the 28-day deletion rule lazily.
func (d *Device) spk(id uint32, now int64) *SPKRecord {
	for i := range d.SPKs {
		s := &d.SPKs[i]
		if s.ID == id && now-s.CreatedAt <= SPKPrivMaxAge {
			return s
		}
	}
	return nil
}

// opk returns the stored OPK with id, applying the 7-day grace rule lazily.
func (d *Device) opk(id uint32, now int64) *OPKRecord {
	for i := range d.OPKs {
		o := &d.OPKs[i]
		if o.ID == id && (o.ConsumedReportedAt == 0 || now-o.ConsumedReportedAt <= OPKGrace) {
			return o
		}
	}
	return nil
}

// Publish returns the bundle to register (newest SPK, no OPK) and the OPK
// batch to upload (every stored key not yet reported consumed).
func (d *Device) Publish() (Bundle, []OPK) {
	if len(d.SPKs) == 0 {
		panic("kilitcrypto: Publish without an SPK")
	}
	spk := d.SPKs[0]
	for _, s := range d.SPKs[1:] {
		if s.CreatedAt >= spk.CreatedAt {
			spk = s
		}
	}
	pub, _ := X25519PublicKey(spk.Priv)
	b := Bundle{
		Username: d.Identity.Username, IKSig: d.Identity.IKSigPub(), IKDH: d.Identity.IKDHPub(),
		IKBindSig: d.Identity.IKBindSig(), SPKID: spk.ID, SPKPub: pub, SPKCreatedAt: uint64(spk.CreatedAt),
		SPKSig: Sign(d.Identity.IKSigSeed, SPKMessage(spk.ID, uint64(spk.CreatedAt), pub)),
	}
	var opks []OPK
	for _, o := range d.OPKs {
		if o.ConsumedReportedAt != 0 {
			continue
		}
		p, _ := X25519PublicKey(o.Priv)
		opks = append(opks, OPK{ID: o.ID, Pub: p})
	}
	return b, opks
}

// RotateIdentity replaces the device's identity keys (re-registration). Every
// session was bound to the old keys in its AD, so all of them become
// superseded (oldIdentity); the new SPK/OPKs are added by the caller.
func (d *Device) RotateIdentity(id Identity) []Action {
	d.Identity = id
	var acts []Action
	for _, p := range d.Peers {
		for _, s := range p.Sessions {
			if !s.Superseded {
				s.Superseded, s.SupersededReason = true, SupersededOldIdentity
				acts = append(acts, Action{Kind: ActSuperseded, Peer: p.Username, SID: s.SID, Reason: SupersededOldIdentity})
			}
		}
	}
	return acts
}

// ---- peers and sessions ----

// PeerState returns the peer record, or nil if the device has never heard of
// the username.
func (d *Device) PeerState(username string) *Peer { return d.Peers[username] }

func (d *Device) peer(username string) *Peer {
	p := d.Peers[username]
	if p == nil {
		p = &Peer{Username: username}
		d.Peers[username] = p
	}
	return p
}

// Session finds a session by sid among all sessions with the peer, live or
// superseded.
func (d *Device) Session(peer string, sid [8]byte) *Session {
	if p := d.Peers[peer]; p != nil {
		return p.session(sid)
	}
	return nil
}

func (p *Peer) session(sid [8]byte) *Session {
	for _, s := range p.Sessions {
		if s.SID == sid {
			return s
		}
	}
	return nil
}

func (p *Peer) knownSID(sid [8]byte, now int64) *KnownSID {
	for i := range p.KnownSIDs {
		k := &p.KnownSIDs[i]
		if k.SID == sid && now-k.DeletedAt <= KnownSIDMaxAge {
			return k
		}
	}
	return nil
}

func (p *Peer) seenEK(ek []byte, now int64) bool {
	for _, e := range p.SeenEK {
		if bytes.Equal(e.EK, ek) && now-e.SeenAt <= SeenEKMaxAge {
			return true
		}
	}
	return false
}

func (p *Peer) addSeenEK(ek []byte, now int64) {
	p.SeenEK = append(p.SeenEK, SeenEK{EK: dup(ek), SeenAt: now})
	if len(p.SeenEK) > SeenEKMax {
		p.SeenEK = p.SeenEK[len(p.SeenEK)-SeenEKMax:]
	}
}

func (p *Peer) isProcessed(msgID string, now int64) bool {
	for _, e := range p.ProcessedMsgIDs {
		if e.MsgID == msgID && now-e.At <= ProcessedMaxAge {
			return true
		}
	}
	return false
}

func (p *Peer) addProcessed(msgID string, now int64) {
	p.ProcessedMsgIDs = append(p.ProcessedMsgIDs, ProcessedID{MsgID: msgID, At: now})
	if len(p.ProcessedMsgIDs) > ProcessedMax {
		p.ProcessedMsgIDs = p.ProcessedMsgIDs[len(p.ProcessedMsgIDs)-ProcessedMax:]
	}
}

func (p *Peer) isDuplicate(author Author, id string, now int64) bool {
	for _, e := range p.Dedupe {
		if e.Author == author && e.ID == id && now-e.At <= DedupeMaxAge {
			return true
		}
	}
	return false
}

func (p *Peer) addDedupe(author Author, id string, now int64) {
	p.Dedupe = append(p.Dedupe, DedupeEntry{Author: author, ID: id, At: now})
	if len(p.Dedupe) > DedupeMax {
		p.Dedupe = p.Dedupe[len(p.Dedupe)-DedupeMax:]
	}
}

func (p *Peer) parkedIndex(msgID string) int {
	for i, e := range p.Parked {
		if e.MsgID == msgID {
			return i
		}
	}
	return -1
}

// addSession appends a session and enforces the 4-per-peer cap by deleting
// the oldest superseded session (sid kept in known_sids as pruned).
func (d *Device) addSession(p *Peer, s *Session, now int64) []Action {
	p.Sessions = append(p.Sessions, s)
	if p.Contact != nil {
		p.Contact.WMSecrets = append(p.Contact.WMSecrets, WMSecret{SID: s.SID, WS: dup(s.WS)})
	}
	var acts []Action
	for len(p.Sessions) > SessionsPerPeer {
		victim := -1
		for i, c := range p.Sessions {
			if c.Superseded && (victim < 0 || c.CreatedAt < p.Sessions[victim].CreatedAt) {
				victim = i
			}
		}
		if victim < 0 {
			break
		}
		acts = append(acts, d.removeSession(p, victim, DeletedPruned, now))
	}
	return acts
}

func (d *Device) removeSession(p *Peer, i int, reason string, now int64) Action {
	s := p.Sessions[i]
	p.Sessions = append(p.Sessions[:i:i], p.Sessions[i+1:]...)
	p.KnownSIDs = append(p.KnownSIDs, KnownSID{SID: s.SID, DeletedReason: reason, DeletedAt: now})
	if s.Ratchet != nil {
		s.Ratchet.Zeroize()
	}
	return Action{Kind: ActSessionDeleted, Peer: p.Username, SID: s.SID, Reason: reason}
}

// DeleteSession deletes a session and records its sid in known_sids with
// reason (the delete_session op; a rollback or parse failure that should
// recover at once is LoseSession). It returns false if no such session.
func (d *Device) DeleteSession(peer string, sid [8]byte, reason string, now int64) bool {
	p := d.Peers[peer]
	if p == nil {
		return false
	}
	for i, s := range p.Sessions {
		if s.SID == sid {
			d.removeSession(p, i, reason, now)
			return true
		}
	}
	return false
}

// LoseSession is S3: the session file failed the rollback check or could not
// be parsed, so the session is deleted (known_sids reason rollback or
// parse_failure) and a fresh session whose first message is
// ctrl.resync{lost_sid} is initiated at once.
func (d *Device) LoseSession(peer string, sid [8]byte, reason string, now int64) []Action {
	if !d.DeleteSession(peer, sid, reason, now) {
		return nil
	}
	p := d.peer(peer)
	acts := []Action{{Kind: ActSessionDeleted, Peer: peer, SID: sid, Reason: reason}}
	return append(acts, d.initiateResync(p, sid, now)...)
}

// SendingSession applies the sending-session rule of §3.2: among
// non-superseded sessions, the lexicographically smallest sid of those with
// lastActivity; otherwise the newest own-initiated one; otherwise nil (fetch a
// bundle and initiate).
func (d *Device) SendingSession(peer string) *Session {
	p := d.Peers[peer]
	if p == nil {
		return nil
	}
	var best *Session
	for _, s := range p.Sessions {
		if s.Superseded || !s.HasActivity() {
			continue
		}
		if best == nil || bytes.Compare(s.SID[:], best.SID[:]) < 0 {
			best = s
		}
	}
	if best != nil {
		return best
	}
	for _, s := range p.Sessions {
		if s.Superseded || s.Role != RoleInitiator {
			continue
		}
		if best == nil || s.CreatedAt >= best.CreatedAt {
			best = s
		}
	}
	return best
}

// SendingSID is SendingSession's sid, ok = false when there is none.
func (d *Device) SendingSID(peer string) (sid [8]byte, ok bool) {
	if s := d.SendingSession(peer); s != nil {
		return s.SID, true
	}
	return sid, false
}

func sameIdentity(a, b PeerIdentity) bool { return CheckIdentity(a, b) == nil }

// ---- contact actions ----

// AcceptMessageRequest is "Kabul et" (§3.2 step 4). When the device has no
// record for the peer yet (the user adds the contact from the directory
// before any message arrived) the record is created from a lookup; it
// returns false if no record exists and none could be created.
func (d *Device) AcceptMessageRequest(peer string) bool {
	p := d.peer(peer)
	if p.Contact == nil {
		res := d.lookup(peer)
		if res.Status != LookupOK || res.Identity == nil {
			return false
		}
		p.Contact = &Contact{Identity: PeerIdentity{Username: peer, IKSig: dup(res.Identity.IKSig), IKDH: dup(res.Identity.IKDH)}}
	}
	p.Contact.Accepted = true
	return true
}

// AcceptKeyChange is "Yeni anahtarı kabul et" (§3.2 step 1, S2): the record
// is replaced, every session whose AD identity keys differ becomes
// superseded (oldIdentity), wm_secrets is reset and the parked key_change
// envelopes of the peer are re-run.
func (d *Device) AcceptKeyChange(peer string, now int64) []Action {
	p := d.Peers[peer]
	if p == nil || p.Contact == nil || p.Contact.KeyChange == nil {
		return nil
	}
	c := p.Contact
	c.Identity = *c.KeyChange
	c.KeyChange = nil
	c.Verified = false
	c.WMSecrets = nil
	var acts []Action
	for _, s := range p.Sessions {
		if !s.Superseded && !sameIdentity(s.Peer, c.Identity) {
			s.Superseded, s.SupersededReason = true, SupersededOldIdentity
			acts = append(acts, Action{Kind: ActSuperseded, Peer: peer, SID: s.SID, Reason: SupersededOldIdentity})
		}
	}
	return append(acts, d.rerunParked(p, ParkKeyChange, nil, now)...)
}

// ---- sending ----

// Send encrypts an inner message to peer on the sending session, initiating
// a session first when there is none. The envelope is appended to Outbox and
// returned; own text/image messages are appended to the conversation.
func (d *Device) Send(peer string, inner *Inner, now int64) (*Outbound, []Action, error) {
	p := d.peer(peer)
	if p.Contact != nil && p.Contact.KeyChange != nil {
		return nil, nil, ErrKeyChangePending
	}
	var acts []Action
	s := d.SendingSession(peer)
	if s == nil {
		var err error
		var more []Action
		s, more, err = d.initiateSession(p, now)
		acts = append(acts, more...)
		if err != nil {
			return nil, acts, err
		}
	}
	out, err := d.sendOn(p, s, inner, now, false)
	if err != nil {
		return nil, acts, err
	}
	if n := len(acts); n > 0 && acts[n-1].Kind == ActInitiate {
		acts[n-1].Outbound = out
	}
	return out, acts, nil
}

// initiateSession fetches a bundle and runs X3DH + RatchetInitAlice.
func (d *Device) initiateSession(p *Peer, now int64) (*Session, []Action, error) {
	b, err := d.Directory.FetchBundle(p.Username)
	if err != nil {
		return nil, []Action{{Kind: ActInitiateFailed, Peer: p.Username, Err: err}}, err
	}
	var known *PeerIdentity
	if p.Contact != nil {
		known = &p.Contact.Identity
	}
	res, err := Initiate(d.Identity, *b, known, now, d.ks)
	if err != nil {
		if errors.Is(err, ErrIdentityMismatch) && p.Contact != nil {
			// Key change detected on fetch (§3.6): banner, sending disabled.
			p.Contact.KeyChange = &PeerIdentity{Username: b.Username, IKSig: dup(b.IKSig), IKDH: dup(b.IKDH)}
			return nil, []Action{{Kind: ActKeyChange, Peer: p.Username}}, ErrKeyChangePending
		}
		return nil, []Action{{Kind: ActInitiateFailed, Peer: p.Username, Err: err}}, err
	}
	st, err := InitAlice(res.SK, b.SPKPub, d.ks)
	if err != nil {
		return nil, []Action{{Kind: ActInitiateFailed, Peer: p.Username, Err: err}}, err
	}
	peerID := PeerIdentity{Username: b.Username, IKSig: dup(b.IKSig), IKDH: dup(b.IKDH)}
	if p.Contact == nil {
		p.Contact = &Contact{Identity: peerID, Accepted: true}
	}
	s := &Session{
		SID: res.SID, Role: RoleInitiator, CreatedAt: now, WS: dup(res.WS), AD: res.AD,
		Local: d.LocalIdentity(), Peer: peerID, Ratchet: st,
		PendingX3DH: &PendingX3DH{EKPub: res.EKPub, SPKID: res.SPKID, OPKID: res.OPKID},
	}
	res.Zeroize()
	acts := d.addSession(p, s, now)
	return s, append(acts, Action{Kind: ActInitiate, Peer: p.Username, SID: s.SID}), nil
}

// sendOn encrypts inner on s: EncodeInner → Pad → RatchetEncrypt →
// EncodeEnvelope (kind prekey while pendingX3DH is present).
func (d *Device) sendOn(p *Peer, s *Session, inner *Inner, now int64, resend bool) (*Outbound, error) {
	raw, err := EncodeInner(inner)
	if err != nil {
		return nil, err
	}
	pt, err := Pad(raw)
	if err != nil {
		return nil, err
	}
	enc, err := s.Ratchet.Encrypt(pt, s.AD, s.SID)
	if err != nil {
		return nil, err
	}
	kind := KindMsg
	var x *X3DHParsed
	if s.PendingX3DH != nil {
		kind = KindPrekey
		x = &X3DHParsed{
			EK: s.PendingX3DH.EKPub, IKBindSig: d.Identity.IKBindSig(), IKDH: d.Identity.IKDHPub(),
			IKSig: d.Identity.IKSigPub(), OPKID: s.PendingX3DH.OPKID, SPKID: s.PendingX3DH.SPKID,
		}
	}
	env, err := EncodeEnvelope(kind, s.SID, enc.Header, enc.Wire, x)
	if err != nil {
		return nil, err
	}
	out := &Outbound{To: p.Username, MsgID: d.NextMsgID(), Envelope: env, SID: s.SID, Kind: kind, InnerID: inner.ID, T: inner.T, Resend: resend}
	d.Outbox = append(d.Outbox, *out)
	if inner.T == TText || inner.T == TImage {
		if m := p.message(AuthorMe, inner.ID); m != nil {
			m.SentOnSID, m.MsgID = s.SID, out.MsgID
		} else {
			m := &Message{Author: AuthorMe, ID: inner.ID, T: inner.T, Ts: inner.Ts, Ttl: inner.Ttl, Att: inner.Att, SentOnSID: s.SID, SentAt: now, MsgID: out.MsgID}
			if inner.Text != nil {
				m.Text = *inner.Text
			}
			p.Messages = append(p.Messages, m)
		}
	}
	return out, nil
}

func (p *Peer) message(author Author, id string) *Message {
	for _, m := range p.Messages {
		if m.Author == author && m.ID == id {
			return m
		}
	}
	return nil
}

// DrainOutbox returns and clears the outbox.
func (d *Device) DrainOutbox() []Outbound {
	out := d.Outbox
	d.Outbox = nil
	return out
}

// ResyncResendSet is the set a ctrl.resync{lost_sid} receiver re-sends
// (§3.4): own text/image messages sent on lost_sid within the last 7 days and
// still stored, oldest first, at most 50.
func (d *Device) ResyncResendSet(peer string, lostSID [8]byte, now int64) []*Message {
	p := d.Peers[peer]
	if p == nil {
		return nil
	}
	var set []*Message
	for _, m := range p.Messages {
		if m.Author == AuthorMe && m.SentOnSID == lostSID && now-m.SentAt <= ResendWindow {
			set = append(set, m)
		}
	}
	sort.SliceStable(set, func(i, j int) bool { return set[i].SentAt < set[j].SentAt })
	if len(set) > ResendMax {
		set = set[:ResendMax]
	}
	return set
}

// recoveryAllowed is the per-peer 10-minute bound shared by the
// rejected-initiation path and the unknown_sid S3 trigger.
func (p *Peer) recoveryAllowed(now int64) bool {
	return p.RecoveryAt == 0 || now-p.RecoveryAt >= RecoveryInterval
}

// initiateResync initiates a fresh session whose first inner message is
// ctrl.resync{lost_sid} and stamps the per-peer recovery bound.
func (d *Device) initiateResync(p *Peer, lostSID [8]byte, now int64) []Action {
	p.RecoveryAt = now
	s, acts, err := d.initiateSession(p, now)
	if err != nil {
		return acts
	}
	lost := Base64url(lostSID[:])
	out, err := d.sendOn(p, s, &Inner{T: TResync, ID: d.NextInnerID(), Ts: now, LostSid: &lost}, now, false)
	if err != nil {
		return append(acts, Action{Kind: ActInitiateFailed, Peer: p.Username, Err: err})
	}
	l := lostSID
	acts[len(acts)-1].LostSID = &l
	acts[len(acts)-1].Outbound = out
	return acts
}

// ---- acks ----

// ack is the index.json write of §3.2b step 5: the cursor advances and the
// msg_id joins pendingAcks in the same write, whatever the outcome was.
func (d *Device) ack(in Inbound) Action {
	d.advanceCursor(in.ServerID)
	d.PendingAcks = append(d.PendingAcks, in.MsgID)
	if len(d.PendingAcks) > PendingAcksMax {
		d.PendingAcks = d.PendingAcks[len(d.PendingAcks)-PendingAcksMax:]
	}
	return Action{Kind: ActAck, MsgID: in.MsgID}
}

// advanceCursor: cursor = max server id of envelopes stored, parked or classified.
func (d *Device) advanceCursor(id uint64) {
	if id > d.Cursor {
		d.Cursor = id
	}
}

// ConfirmAcks removes ids the server confirmed deleted from pendingAcks.
func (d *Device) ConfirmAcks(ids []string) {
	done := map[string]bool{}
	for _, id := range ids {
		done[id] = true
	}
	kept := d.PendingAcks[:0]
	for _, id := range d.PendingAcks {
		if !done[id] {
			kept = append(kept, id)
		}
	}
	d.PendingAcks = kept
}

// MessageIDs returns the ordered (author, id) list of a conversation (the
// expect_messages form of §3.9).
func (d *Device) MessageIDs(peer string) [][2]string {
	p := d.Peers[peer]
	if p == nil {
		return nil
	}
	out := make([][2]string, 0, len(p.Messages))
	for _, m := range p.Messages {
		out = append(out, [2]string{string(m.Author), m.ID})
	}
	return out
}

// ---- maintenance (launch / foreground / hourly) ----

// Maintenance applies every time-based rule at now: parked expiry and
// lookup retries, seen_ek / known_sids / processed_msg_ids / dedupe windows,
// SPK and OPK private-key deletion, deletion of superseded sessions.
func (d *Device) Maintenance(now int64) []Action {
	var acts []Action
	for i := 0; i < len(d.SPKs); {
		if now-d.SPKs[i].CreatedAt > SPKPrivMaxAge {
			acts = append(acts, Action{Kind: ActKeyDeleted, Reason: "spk", KeyID: d.SPKs[i].ID})
			clear(d.SPKs[i].Priv)
			d.SPKs = append(d.SPKs[:i:i], d.SPKs[i+1:]...)
			continue
		}
		i++
	}
	for i := 0; i < len(d.OPKs); {
		if o := d.OPKs[i]; o.ConsumedReportedAt != 0 && now-o.ConsumedReportedAt > OPKGrace {
			acts = append(acts, Action{Kind: ActKeyDeleted, Reason: "opk", KeyID: o.ID})
			d.removeOPK(i)
			continue
		}
		i++
	}
	names := make([]string, 0, len(d.Peers))
	for n := range d.Peers {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		acts = append(acts, d.maintainPeer(d.Peers[n], now)...)
	}
	return acts
}

func (d *Device) maintainPeer(p *Peer, now int64) []Action {
	var acts []Action
	for i := 0; i < len(p.Sessions); {
		s := p.Sessions[i]
		last := s.LastActivity
		if last == 0 {
			last = s.CreatedAt
		}
		if s.Superseded && now-last > SupersededMaxAge {
			acts = append(acts, d.removeSession(p, i, DeletedPruned, now))
			continue
		}
		i++
	}
	kept := p.SeenEK[:0]
	for _, e := range p.SeenEK {
		if now-e.SeenAt <= SeenEKMaxAge {
			kept = append(kept, e)
		}
	}
	p.SeenEK = kept
	ks := p.KnownSIDs[:0]
	for _, k := range p.KnownSIDs {
		if now-k.DeletedAt <= KnownSIDMaxAge {
			ks = append(ks, k)
		}
	}
	p.KnownSIDs = ks
	pr := p.ProcessedMsgIDs[:0]
	for _, e := range p.ProcessedMsgIDs {
		if now-e.At <= ProcessedMaxAge {
			pr = append(pr, e)
		}
	}
	p.ProcessedMsgIDs = pr
	dd := p.Dedupe[:0]
	for _, e := range p.Dedupe {
		if now-e.At <= DedupeMaxAge {
			dd = append(dd, e)
		}
	}
	p.Dedupe = dd
	// Parked expiry and lookup retries; the list is walked by msg_id because
	// a retry may resolve (remove) or re-park (append) its entry.
	ids := make([]string, 0, len(p.Parked))
	for _, e := range p.Parked {
		ids = append(ids, e.MsgID)
	}
	for _, id := range ids {
		i := p.parkedIndex(id)
		if i < 0 {
			continue
		}
		e := p.Parked[i]
		age := now - e.ReceivedAt
		var expired, reason string
		switch e.Reason {
		case ParkKeyChange:
			if age > ParkedKeyChangeTTL {
				expired, reason = e.Reason, ReasonKeyChangeExpired
			}
		case ParkUnknownSID:
			if age > ParkedUnknownSIDTTL {
				expired, reason = e.Reason, ReasonUnknownSID
			}
		case ParkLookupDeferred:
			if age > ParkedLookupTTL {
				expired, reason = e.Reason, ReasonLookupFailed
			} else if now >= e.NextRetryAt {
				acts = append(acts, d.rerunParkedEntry(p, e, now)...)
			}
		}
		if expired != "" {
			p.Parked = append(p.Parked[:i:i], p.Parked[i+1:]...)
			acts = append(acts, d.classify(p, e.inbound(), reason, now)...)
		}
	}
	return acts
}

func (e *Parked) inbound() Inbound {
	return Inbound{ServerID: e.ServerID, MsgID: e.MsgID, From: e.From, Envelope: e.Envelope}
}

// ---- in-memory server (test double, also used by the vector generator) ----

// MemServer is a minimal store-and-forward server: bundles with OPK claims,
// a per-recipient queue with monotonic ids, msg_id idempotency and acks.
type MemServer struct {
	users  map[string]*memUser
	rows   []MemRow
	nextID uint64
	// Offline makes FetchBundle and LookupUser fail transiently.
	Offline bool
	// BundleFetches counts FetchBundle calls per username.
	BundleFetches map[string]int
}

type memUser struct {
	bundle   Bundle // without OPK
	opks     []OPK
	consumed []uint32
}

// MemRow is one queued envelope.
type MemRow struct {
	ID       uint64
	From     string
	To       string
	MsgID    string
	Envelope []byte
}

// NewMemServer creates an empty server.
func NewMemServer() *MemServer {
	return &MemServer{users: map[string]*memUser{}, BundleFetches: map[string]int{}}
}

// Register publishes (or replaces) a user's bundle and OPK batch.
func (s *MemServer) Register(b Bundle, opks []OPK) {
	u := &memUser{bundle: b}
	for _, o := range opks {
		u.opks = append(u.opks, OPK{ID: o.ID, Pub: dup(o.Pub)})
	}
	s.users[b.Username] = u
}

// FetchBundle serves the bundle and claims the first OPK (none → SPK-only).
func (s *MemServer) FetchBundle(peer string) (*Bundle, error) {
	s.BundleFetches[peer]++
	if s.Offline {
		return nil, ErrOffline
	}
	u := s.users[peer]
	if u == nil {
		return nil, ErrUnknownUser
	}
	b := u.bundle
	if len(u.opks) > 0 {
		o := u.opks[0]
		u.opks = u.opks[1:]
		u.consumed = append(u.consumed, o.ID)
		id := o.ID
		b.OPKID, b.OPKPub = &id, o.Pub
	}
	return &b, nil
}

// LookupUser is GET /v1/users/{peer}.
func (s *MemServer) LookupUser(peer string) LookupResult {
	if s.Offline {
		return LookupResult{Status: LookupTransient}
	}
	u := s.users[peer]
	if u == nil {
		return LookupResult{Status: LookupNotFound}
	}
	return LookupResult{Status: LookupOK, Identity: &PeerIdentity{Username: peer, IKSig: u.bundle.IKSig, IKDH: u.bundle.IKDH}}
}

// Consumed returns the OPK ids claimed so far for user (the consumed_ids report).
func (s *MemServer) Consumed(user string) []uint32 {
	if u := s.users[user]; u != nil {
		return append([]uint32(nil), u.consumed...)
	}
	return nil
}

// OPKCount returns how many unclaimed OPKs user has on the server.
func (s *MemServer) OPKCount(user string) int {
	if u := s.users[user]; u != nil {
		return len(u.opks)
	}
	return 0
}

// Post is POST /v1/messages: idempotent on (to, msg_id).
func (s *MemServer) Post(from string, out Outbound) uint64 {
	for _, r := range s.rows {
		if r.To == out.To && r.MsgID == out.MsgID {
			return r.ID
		}
	}
	s.nextID++
	s.rows = append(s.rows, MemRow{ID: s.nextID, From: from, To: out.To, MsgID: out.MsgID, Envelope: dup(out.Envelope)})
	return s.nextID
}

// Fetch returns the unacked rows for user with id > after (the drain / poll
// rule of §4.4: a row with id ≤ after is never redelivered).
func (s *MemServer) Fetch(user string, after uint64) []Inbound {
	var out []Inbound
	for _, r := range s.rows {
		if r.To == user && r.ID > after {
			out = append(out, Inbound{ServerID: r.ID, MsgID: r.MsgID, From: r.From, Envelope: r.Envelope})
		}
	}
	return out
}

// Ack deletes the user's rows with the given msg_ids and returns how many.
func (s *MemServer) Ack(user string, ids []string) int {
	set := map[string]bool{}
	for _, id := range ids {
		set[id] = true
	}
	n := 0
	kept := s.rows[:0]
	for _, r := range s.rows {
		if r.To == user && set[r.MsgID] {
			n++
			continue
		}
		kept = append(kept, r)
	}
	s.rows = kept
	return n
}

// Pending returns how many rows are queued for user.
func (s *MemServer) Pending(user string) int {
	n := 0
	for _, r := range s.rows {
		if r.To == user {
			n++
		}
	}
	return n
}
