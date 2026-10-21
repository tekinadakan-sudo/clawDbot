package kilitcrypto

import (
	"bytes"
	"encoding/json"
)

// Size rules of §3.3/§3.4.
const (
	PadBlock       = 256   // ISO/IEC 7816-4 padding to a multiple of 256 bytes
	MaxInnerJSON   = 40960 // inner JSON before padding; larger → ErrSizeLimit
	MaxEnvelope    = 65536 // decoded E2E envelope bytes (server: 413 envelope_too_large)
	MinCiphertext  = PadBlock + 16
	EnvelopeV      = 1
	KindPrekey     = "prekey"
	KindMsg        = "msg"
	tagLen         = 16
	minPaddedBytes = PadBlock
)

// Pad appends 0x80 || 0x00*k to the next multiple of 256 bytes (at least one
// byte is always added). Inputs over MaxInnerJSON are ErrSizeLimit.
func Pad(inner []byte) ([]byte, error) {
	if len(inner) > MaxInnerJSON {
		return nil, ErrSizeLimit
	}
	n := len(inner) + 1
	padded := (n + PadBlock - 1) / PadBlock * PadBlock
	out := make([]byte, padded)
	copy(out, inner)
	out[len(inner)] = 0x80
	return out, nil
}

// Unpad rejects a block that is empty or not a multiple of 256, that is all
// zero, or whose last non-zero byte is not 0x80 (ErrBadPadding).
func Unpad(padded []byte) ([]byte, error) {
	if len(padded) == 0 || len(padded)%PadBlock != 0 {
		return nil, ErrBadPadding
	}
	i := len(padded) - 1
	for i >= 0 && padded[i] == 0x00 {
		i--
	}
	if i < 0 || padded[i] != 0x80 {
		return nil, ErrBadPadding
	}
	return padded[:i], nil
}

// X3DHBlock is the x3dh object of a prekey envelope (§3.4). Fields are in
// alphabetical order; OPKID is a pointer so null and absent both decode to nil.
type X3DHBlock struct {
	EK        string  `json:"ek"`
	IKBindSig string  `json:"ik_bind_sig"`
	IKDH      string  `json:"ik_dh"`
	IKSig     string  `json:"ik_sig"`
	OPKID     *uint32 `json:"opk_id"`
	SPKID     uint32  `json:"spk_id"`
}

// OuterEnvelope is the wire JSON of the E2E envelope (base64url fields).
type OuterEnvelope struct {
	Ct   string     `json:"ct"`
	Hdr  string     `json:"hdr"`
	Kind string     `json:"kind"`
	Sid  string     `json:"sid"`
	V    int        `json:"v"`
	X3DH *X3DHBlock `json:"x3dh"`
}

// X3DHParsed is the decoded x3dh block.
type X3DHParsed struct {
	EK        []byte
	IKBindSig []byte
	IKDH      []byte
	IKSig     []byte
	OPKID     *uint32
	SPKID     uint32
}

// Envelope is a parsed and validated E2E envelope (§3.2b step 1). For a
// prekey envelope SID is recomputed from EK and the carried sid is ignored.
type Envelope struct {
	Kind   string
	SID    [8]byte
	Header Header
	Hdr    []byte // the 41 raw header bytes
	Ct     []byte
	X3DH   *X3DHParsed
}

// MarshalJSON encodes with sorted struct fields and no HTML escaping (§3).
func marshalJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// EncodeEnvelope builds the E2E envelope bytes. x3dh is nil for kind "msg".
func EncodeEnvelope(kind string, sid [8]byte, hdr, ct []byte, x3dh *X3DHParsed) ([]byte, error) {
	o := OuterEnvelope{Ct: Base64url(ct), Hdr: Base64url(hdr), Kind: kind, Sid: Base64url(sid[:]), V: EnvelopeV}
	if x3dh != nil {
		o.X3DH = &X3DHBlock{
			EK: Base64url(x3dh.EK), IKBindSig: Base64url(x3dh.IKBindSig), IKDH: Base64url(x3dh.IKDH),
			IKSig: Base64url(x3dh.IKSig), OPKID: x3dh.OPKID, SPKID: x3dh.SPKID,
		}
	}
	b, err := marshalJSON(o)
	if err != nil {
		return nil, err
	}
	if len(b) > MaxEnvelope {
		return nil, ErrSizeLimit
	}
	return b, nil
}

// ParseEnvelope is §3.2b step 1: v != 1, unknown kind, bad or non-8-byte sid,
// ct shorter than 256 + 16, a prekey without a well-formed x3dh block, or a
// decoded envelope over MaxEnvelope → ErrBadEnvelope; hdr not exactly 41
// bytes or hdr[0] != 0x01 → ErrBadHeader. Nothing here touches a KDF.
func ParseEnvelope(b []byte) (*Envelope, error) {
	if len(b) > MaxEnvelope {
		return nil, ErrBadEnvelope
	}
	var o OuterEnvelope
	dec := json.NewDecoder(bytes.NewReader(b))
	if err := dec.Decode(&o); err != nil {
		return nil, ErrBadEnvelope
	}
	if o.V != EnvelopeV || (o.Kind != KindPrekey && o.Kind != KindMsg) {
		return nil, ErrBadEnvelope
	}
	sidBytes, err := Base64urlDecode(o.Sid)
	if err != nil || len(sidBytes) != 8 {
		return nil, ErrBadEnvelope
	}
	hdr, err := Base64urlDecode(o.Hdr)
	if err != nil {
		return nil, ErrBadEnvelope
	}
	h, err := ParseHeader(hdr)
	if err != nil {
		return nil, err
	}
	ct, err := Base64urlDecode(o.Ct)
	if err != nil || len(ct) < MinCiphertext {
		return nil, ErrBadEnvelope
	}
	e := &Envelope{Kind: o.Kind, Header: h, Hdr: hdr, Ct: ct}
	copy(e.SID[:], sidBytes)
	if o.Kind == KindPrekey {
		if o.X3DH == nil {
			return nil, ErrBadEnvelope
		}
		x := &X3DHParsed{SPKID: o.X3DH.SPKID}
		for _, f := range []struct {
			dst  *[]byte
			src  string
			size int
		}{{&x.EK, o.X3DH.EK, 32}, {&x.IKBindSig, o.X3DH.IKBindSig, 64}, {&x.IKDH, o.X3DH.IKDH, 32}, {&x.IKSig, o.X3DH.IKSig, 32}} {
			v, err := Base64urlDecode(f.src)
			if err != nil || len(v) != f.size {
				return nil, ErrBadEnvelope
			}
			*f.dst = v
		}
		if o.X3DH.OPKID != nil {
			id := *o.X3DH.OPKID
			x.OPKID = &id
		}
		e.X3DH = x
		e.SID = SID(x.EK)
	} else if o.X3DH != nil {
		return nil, ErrBadEnvelope
	}
	return e, nil
}

// Attach is the att object of an image message (§3.4).
type Attach struct {
	Blob   string `json:"blob"` // hex32 blob_id
	H      int    `json:"h"`
	Key    string `json:"key"` // base64url(fileKey 32)
	Len    uint64 `json:"len"`
	Mime   string `json:"mime"`
	Sha256 string `json:"sha256"` // base64url(32)
	W      int    `json:"w"`
}

// Inner is the plaintext message of §3.4 (every t in one struct; fields in
// alphabetical order). Pointer fields that are absent or null decode to nil.
// Att and Ref are emitted as null when unset (Go *T convention of §3); the
// type-specific scalars are omitted when unset — receivers treat both alike.
type Inner struct {
	Att     *Attach  `json:"att"`
	Count   *int     `json:"count,omitempty"`
	ID      string   `json:"id"`
	Kind    *string  `json:"kind,omitempty"`
	LostSid *string  `json:"lost_sid,omitempty"`
	Ref     []string `json:"ref"`
	SeqFrom *uint64  `json:"seq_from,omitempty"`
	SeqTo   *uint64  `json:"seq_to,omitempty"`
	T       string   `json:"t"`
	Text    *string  `json:"text,omitempty"`
	Timer   *int     `json:"timer,omitempty"`
	Ts      int64    `json:"ts"`
	Ttl     int      `json:"ttl"`
}

// EncodeInner serialises an inner message (sorted keys, no HTML escaping).
func EncodeInner(m *Inner) ([]byte, error) { return marshalJSON(m) }

// DecodeInner parses an inner message; absent and null are identical.
func DecodeInner(b []byte) (*Inner, error) {
	var m Inner
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, ErrBadEnvelope
	}
	if m.T == "" || m.ID == "" {
		return nil, ErrBadEnvelope
	}
	return &m, nil
}
