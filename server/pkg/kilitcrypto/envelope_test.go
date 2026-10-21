package kilitcrypto

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestPadding(t *testing.T) {
	cases := []struct{ in, padded int }{{0, 256}, {1, 256}, {254, 256}, {255, 256}, {256, 512}, {511, 512}, {40960, 41216}}
	for _, c := range cases {
		in := bytes.Repeat([]byte{'x'}, c.in)
		p, err := Pad(in)
		if err != nil || len(p) != c.padded {
			t.Fatalf("Pad(%d) len %d, %v", c.in, len(p), err)
		}
		if p[c.in] != 0x80 || !bytes.Equal(p[:c.in], in) {
			t.Fatalf("Pad(%d) layout", c.in)
		}
		for _, b := range p[c.in+1:] {
			if b != 0 {
				t.Fatalf("Pad(%d) trailing byte %x", c.in, b)
			}
		}
		out, err := Unpad(p)
		if err != nil || !bytes.Equal(out, in) {
			t.Fatalf("Unpad(%d): %v", c.in, err)
		}
	}
	if _, err := Pad(make([]byte, 40961)); !errors.Is(err, ErrSizeLimit) {
		t.Errorf("40961 must be sizeLimit, got %v", err)
	}
	if p, err := Pad(make([]byte, 40960)); err != nil || len(p) != 41216 {
		t.Errorf("40960 must pad to 41216: %d %v", len(p), err)
	}
}

func TestUnpadNegatives(t *testing.T) {
	missing80 := bytes.Repeat([]byte{'x'}, 256) // no 0x80 anywhere
	allZero := make([]byte, 256)
	wrongMarker := append(bytes.Repeat([]byte{'x'}, 255), 0x81)
	trailing := make([]byte, 512)
	trailing[0] = 0x80
	trailing[511] = 0x01 // last non-zero byte is 0x01, not 0x80
	for name, in := range map[string][]byte{
		"empty": {}, "len_255": make([]byte, 255), "len_257": make([]byte, 257),
		"missing_0x80": missing80, "all_zero": allZero, "wrong_marker": wrongMarker, "trailing_nonzero": trailing,
	} {
		if _, err := Unpad(in); !errors.Is(err, ErrBadPadding) {
			t.Errorf("%s: %v", name, err)
		}
	}
	p := make([]byte, 256)
	p[0] = 0x80
	if out, err := Unpad(p); err != nil || len(out) != 0 {
		t.Errorf("empty payload with marker: %x %v", out, err)
	}
}

func sampleEnvelope(t *testing.T, kind string, withX3DH bool) ([]byte, [8]byte, []byte, []byte) {
	t.Helper()
	ekPub, _ := X25519PublicKey(seedKey(0, 3))
	sid := SID(ekPub)
	hdr := Header{DHPub: bytes.Repeat([]byte{0x11}, 32), PN: 1, N: 2}.Marshal()
	ct := bytes.Repeat([]byte{0xcc}, 256+16)
	var x *X3DHParsed
	if withX3DH {
		id := uint32(1203)
		x = &X3DHParsed{EK: ekPub, IKBindSig: bytes.Repeat([]byte{0x22}, 64), IKDH: bytes.Repeat([]byte{0x33}, 32),
			IKSig: bytes.Repeat([]byte{0x44}, 32), OPKID: &id, SPKID: 7}
	}
	b, err := EncodeEnvelope(kind, sid, hdr, ct, x)
	if err != nil {
		t.Fatal(err)
	}
	return b, sid, hdr, ct
}

func TestEnvelopeEncodeParse(t *testing.T) {
	b, sid, hdr, ct := sampleEnvelope(t, KindPrekey, true)
	s := string(b)
	if !strings.HasPrefix(s, `{"ct":"`) || !strings.Contains(s, `"x3dh":{"ek":"`) || strings.Contains(s, "\\u003c") {
		t.Fatalf("encoding: %s", s)
	}
	// Keys sorted: ct < hdr < kind < sid < v < x3dh; inside x3dh ek < ik_bind_sig < ik_dh < ik_sig < opk_id < spk_id.
	for _, pair := range [][2]string{{`"ct"`, `"hdr"`}, {`"hdr"`, `"kind"`}, {`"kind"`, `"sid"`}, {`"sid"`, `"v"`}, {`"v"`, `"x3dh"`},
		{`"ek"`, `"ik_bind_sig"`}, {`"ik_bind_sig"`, `"ik_dh"`}, {`"ik_dh"`, `"ik_sig"`}, {`"ik_sig"`, `"opk_id"`}, {`"opk_id"`, `"spk_id"`}} {
		if strings.Index(s, pair[0]) > strings.Index(s, pair[1]) {
			t.Errorf("key order %s before %s", pair[0], pair[1])
		}
	}
	e, err := ParseEnvelope(b)
	if err != nil {
		t.Fatal(err)
	}
	if e.Kind != KindPrekey || e.SID != sid || !bytes.Equal(e.Hdr, hdr) || !bytes.Equal(e.Ct, ct) || e.Header.PN != 1 || e.Header.N != 2 {
		t.Fatal("parsed fields")
	}
	if e.X3DH == nil || e.X3DH.OPKID == nil || *e.X3DH.OPKID != 1203 || e.X3DH.SPKID != 7 || len(e.X3DH.EK) != 32 {
		t.Fatal("x3dh fields")
	}
	// The carried sid is ignored for prekey envelopes: sid is recomputed from ek.
	var o OuterEnvelope
	json.Unmarshal(b, &o)
	o.Sid = Base64url(make([]byte, 8))
	rewritten, _ := json.Marshal(o)
	if e2, err := ParseEnvelope(rewritten); err != nil || e2.SID != sid {
		t.Fatal("prekey sid must be recomputed from ek")
	}
	// msg kind: x3dh null and absent both parse.
	m, _, _, _ := sampleEnvelope(t, KindMsg, false)
	if !strings.Contains(string(m), `"x3dh":null`) {
		t.Fatalf("msg must carry x3dh null: %s", m)
	}
	if e, err := ParseEnvelope(m); err != nil || e.X3DH != nil || e.Kind != KindMsg {
		t.Fatalf("msg parse: %v", err)
	}
	absent := strings.Replace(string(m), `,"x3dh":null`, "", 1)
	if e, err := ParseEnvelope([]byte(absent)); err != nil || e.X3DH != nil {
		t.Fatalf("msg absent x3dh: %v", err)
	}
	// opk_id null and absent are identical.
	nullOPK := strings.Replace(s, `"opk_id":1203`, `"opk_id":null`, 1)
	absentOPK := strings.Replace(s, `"opk_id":1203,`, ``, 1)
	for _, v := range []string{nullOPK, absentOPK} {
		e, err := ParseEnvelope([]byte(v))
		if err != nil || e.X3DH.OPKID != nil {
			t.Fatalf("opk null/absent: %v", err)
		}
	}
}

func TestEnvelopeNegatives(t *testing.T) {
	good, _, _, _ := sampleEnvelope(t, KindPrekey, true)
	variant := func(mod func(o *OuterEnvelope)) []byte {
		var o OuterEnvelope
		if err := json.Unmarshal(good, &o); err != nil {
			t.Fatal(err)
		}
		mod(&o)
		b, _ := json.Marshal(o)
		return b
	}
	hdr40 := Header{DHPub: bytes.Repeat([]byte{0x11}, 31), PN: 1, N: 2}.Marshal()
	hdrV2 := append([]byte{0x02}, bytes.Repeat([]byte{0}, 40)...)
	cases := map[string]struct {
		in  []byte
		err error
	}{
		"v2":             {variant(func(o *OuterEnvelope) { o.V = 2 }), ErrBadEnvelope},
		"kind":           {variant(func(o *OuterEnvelope) { o.Kind = "other" }), ErrBadEnvelope},
		"sid_missing":    {variant(func(o *OuterEnvelope) { o.Sid = "" }), ErrBadEnvelope},
		"sid_7":          {variant(func(o *OuterEnvelope) { o.Sid = Base64url(make([]byte, 7)) }), ErrBadEnvelope},
		"sid_9":          {variant(func(o *OuterEnvelope) { o.Sid = Base64url(make([]byte, 9)) }), ErrBadEnvelope},
		"sid_padding":    {variant(func(o *OuterEnvelope) { o.Sid = "AAAAAAAAAAA=" }), ErrBadEnvelope},
		"sid_alphabet":   {variant(func(o *OuterEnvelope) { o.Sid = "AAAAAAAAAA+" }), ErrBadEnvelope},
		"hdr_40":         {variant(func(o *OuterEnvelope) { o.Hdr = Base64url(hdr40) }), ErrBadHeader},
		"hdr_42":         {variant(func(o *OuterEnvelope) { o.Hdr = Base64url(append(hdrV2, 0)) }), ErrBadHeader},
		"hdr_v2":         {variant(func(o *OuterEnvelope) { o.Hdr = Base64url(hdrV2) }), ErrBadHeader},
		"hdr_bad_b64":    {variant(func(o *OuterEnvelope) { o.Hdr = "A" }), ErrBadEnvelope},
		"ct_short":       {variant(func(o *OuterEnvelope) { o.Ct = Base64url(bytes.Repeat([]byte{0xcc}, 271)) }), ErrBadEnvelope},
		"prekey_no_x3dh": {variant(func(o *OuterEnvelope) { o.X3DH = nil }), ErrBadEnvelope},
		"ek_31":          {variant(func(o *OuterEnvelope) { o.X3DH.EK = Base64url(mustEK()[:31]) }), ErrBadEnvelope},
		"ik_bind_63":     {variant(func(o *OuterEnvelope) { o.X3DH.IKBindSig = Base64url(make([]byte, 63)) }), ErrBadEnvelope},
		"msg_with_x3dh":  {variant(func(o *OuterEnvelope) { o.Kind = KindMsg }), ErrBadEnvelope},
		"not_json":       {[]byte("{"), ErrBadEnvelope},
		"empty":          {nil, ErrBadEnvelope},
		"too_large":      {append(append([]byte(nil), good...), bytes.Repeat([]byte{' '}, MaxEnvelope)...), ErrBadEnvelope},
	}
	for name, c := range cases {
		if _, err := ParseEnvelope(c.in); !errors.Is(err, c.err) {
			t.Errorf("%s: err = %v, want %v", name, err, c.err)
		}
	}
	if _, err := ParseEnvelope(good); err != nil {
		t.Fatalf("control: %v", err)
	}
}

func mustEK() []byte {
	ek, _ := X25519PublicKey(seedKey(0, 3))
	return ek
}

func TestInnerRoundTrip(t *testing.T) {
	text := "merhaba <b> & ü"
	m := &Inner{T: "text", ID: "9f1c", Ts: 1760000000, Ttl: 86400, Text: &text}
	b, err := EncodeInner(m)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if strings.Contains(s, "\\u003c") || strings.Contains(s, "\\u0026") || !strings.Contains(s, `"text":"merhaba <b> & ü"`) {
		t.Fatalf("html escaping: %s", s)
	}
	if !strings.HasPrefix(s, `{"att":null,"id":"9f1c","ref":null,"t":"text","text":`) {
		t.Fatalf("key order/null convention: %s", s)
	}
	back, err := DecodeInner(b)
	if err != nil || back.T != "text" || *back.Text != text || back.Att != nil || back.Ref != nil {
		t.Fatalf("round trip: %+v %v", back, err)
	}
	// absent == null for att/ref; every §3.4 shape decodes field-wise.
	for _, j := range []string{
		`{"t":"text","id":"u","ts":1,"ttl":0,"text":"x"}`,
		`{"t":"text","id":"u","ts":1,"ttl":0,"text":"x","att":null,"ref":null}`,
		`{"t":"image","id":"u","ts":1,"ttl":86400,"att":{"blob":"00","key":"AA","sha256":"AA","mime":"image/jpeg","len":5,"w":1,"h":2}}`,
		`{"t":"ctrl.timer","id":"u","ts":1,"ttl":0,"timer":3600}`,
		`{"t":"ctrl.capture","id":"u","ts":1,"ttl":0,"seq_from":42,"seq_to":44,"count":3,"kind":"screenshot","ref":["a","b"]}`,
		`{"t":"ctrl.capture","id":"u","ts":1,"ttl":0,"kind":"blanking_unavailable","ref":[]}`,
		`{"t":"ctrl.read","id":"u","ts":1,"ttl":0,"ref":["a"]}`,
		`{"t":"ctrl.delete","id":"u","ts":1,"ttl":0,"ref":["a"]}`,
		`{"t":"ctrl.resync","id":"u","ts":1,"ttl":0,"lost_sid":"AAAAAAAAAAA"}`,
	} {
		m, err := DecodeInner([]byte(j))
		if err != nil {
			t.Fatalf("%s: %v", j, err)
		}
		out, _ := EncodeInner(m)
		m2, err := DecodeInner(out)
		if err != nil {
			t.Fatalf("re-decode %s: %v", out, err)
		}
		a, _ := json.Marshal(m)
		b, _ := json.Marshal(m2)
		if !bytes.Equal(a, b) {
			t.Fatalf("field-wise round trip differs: %s vs %s", a, b)
		}
	}
	img, _ := DecodeInner([]byte(`{"t":"image","id":"u","ts":1,"ttl":86400,"att":{"blob":"00","key":"AA","sha256":"AA","mime":"image/jpeg","len":5,"w":1,"h":2}}`))
	if img.Att == nil || img.Att.Len != 5 || img.Att.Mime != "image/jpeg" {
		t.Fatal("att decode")
	}
	cap, _ := DecodeInner([]byte(`{"t":"ctrl.capture","id":"u","ts":1,"ttl":0,"kind":"blanking_unavailable","ref":[]}`))
	if cap.Ref == nil || len(cap.Ref) != 0 || cap.SeqFrom != nil || *cap.Kind != "blanking_unavailable" {
		t.Fatal("capture decode")
	}
	if out, _ := EncodeInner(cap); !strings.Contains(string(out), `"ref":[]`) {
		t.Fatalf("empty ref must stay []: %s", out)
	}
	if _, err := DecodeInner([]byte(`{"id":"u"}`)); !errors.Is(err, ErrBadEnvelope) {
		t.Error("missing t")
	}
	// Size budget end to end: a 40 960-byte inner JSON pads and encrypts; 40 961 does not.
	big := &Inner{T: "text", ID: "u", Ts: 1, Ttl: 0}
	fill := strings.Repeat("a", 40960-len(`{"att":null,"id":"u","ref":null,"t":"text","text":"","ts":1,"ttl":0}`))
	big.Text = &fill
	bb, _ := EncodeInner(big)
	if len(bb) != 40960 {
		t.Fatalf("inner len %d", len(bb))
	}
	if _, err := Pad(bb); err != nil {
		t.Fatal(err)
	}
	fill += "a"
	big.Text = &fill
	bb, _ = EncodeInner(big)
	if _, err := Pad(bb); !errors.Is(err, ErrSizeLimit) {
		t.Fatalf("40961: %v", err)
	}
}
