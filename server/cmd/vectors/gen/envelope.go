package gen

import (
	"bytes"
	"encoding/json"
	"reflect"

	kc "github.com/tekinadakan-sudo/clawDbot/server/pkg/kilitcrypto"
)

// compactJSON is the wire encoding (sorted keys, no HTML escaping) of a value.
func compactJSON(v any) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		panic(err)
	}
	return string(bytes.TrimRight(buf.Bytes(), "\n"))
}

// envelopeSet is envelope.json: padding, the size budget, outer-envelope
// parsing cases (absent vs null optionals, every §3.2b step-1 rejection, the
// maximum-size envelope) and inner messages for the field-wise round trip.
func envelopeSet(x *setA) map[string]any {
	ts := t0
	ttl := 86400
	timer := 3600
	seqFrom, seqTo, count := uint64(42), uint64(44), 3
	screenshot := "screenshot"
	blanking := "blanking_unavailable"
	lost := kc.Base64url(x.sid[:])
	att := &kc.Attach{Blob: hx(bytes.Repeat([]byte{0xab}, 16)), Key: kc.Base64url(seedKey(0x5a, 1)),
		Sha256: kc.Base64url(kc.SHA256([]byte("blob"))), Mime: "image/jpeg", Len: 123456, W: 1200, H: 900}
	inners := []*kc.Inner{
		textInner(innerID("env:text"), "merhaba", ts),
		{T: kc.TImage, ID: innerID("env:image"), Ts: ts, Ttl: ttl, Att: att},
		{T: kc.TTimer, ID: innerID("env:timer"), Ts: ts, Timer: &timer},
		{T: kc.TCapture, ID: innerID("env:capture"), Ts: ts, SeqFrom: &seqFrom, SeqTo: &seqTo, Count: &count, Kind: &screenshot,
			Ref: []string{innerID("env:text"), innerID("env:image")}},
		{T: kc.TCapture, ID: innerID("env:blanking"), Ts: ts, Kind: &blanking, Ref: []string{}},
		{T: kc.TRead, ID: innerID("env:read"), Ts: ts, Ref: []string{innerID("env:text")}},
		{T: kc.TDelete, ID: innerID("env:delete"), Ts: ts, Ref: []string{innerID("env:image")}},
		{T: kc.TResync, ID: innerID("env:resync"), Ts: ts, LostSid: &lost},
	}
	for i := range inners {
		inners[i].Ttl = ttl
	}
	padding := []map[string]any{}
	addPad := func(raw []byte) {
		padded := must(kc.Pad(raw))
		expectEqual("unpad", must(kc.Unpad(padded)), raw)
		padding = append(padding, map[string]any{"json": hx(raw), "padded": hx(padded)})
	}
	for _, m := range inners {
		addPad(must(kc.EncodeInner(m)))
	}
	addPad([]byte{})
	addPad(bytes.Repeat([]byte{'a'}, 255))
	addPad(bytes.Repeat([]byte{'a'}, 256))

	notMultiple := make([]byte, 300)
	notMultiple[0] = 0x80
	missing := make([]byte, 256)
	missing[0] = 0x41
	wrongMark := make([]byte, 256)
	wrongMark[0] = 0x7f
	paddingNeg := []map[string]any{
		{"name": "empty", "padded": "", "error": "badPadding"},
		{"name": "all_zero", "padded": hx(make([]byte, 256)), "error": "badPadding"},
		{"name": "missing_0x80", "padded": hx(missing), "error": "badPadding"},
		{"name": "last_nonzero_not_0x80", "padded": hx(wrongMark), "error": "badPadding"},
		{"name": "len_not_multiple_of_256", "padded": hx(notMultiple), "error": "badPadding"},
	}
	for _, n := range paddingNeg {
		_, err := kc.Unpad(kc.Hex(n["padded"].(string)))
		expectErr("padding "+n["name"].(string), err, "badPadding")
	}
	if _, err := kc.Pad(bytes.Repeat([]byte{0x20}, kc.MaxInnerJSON)); err != nil {
		panic("max inner must pad")
	}
	_, err := kc.Pad(bytes.Repeat([]byte{0x20}, kc.MaxInnerJSON+1))
	expectErr("size limit", err, "sizeLimit")

	// Outer envelopes. Base values: a fixed header, a 272-byte ct, Set A's
	// identity keys and EK in the x3dh block.
	hdr := kc.Header{DHPub: bytes.Repeat([]byte{0x07}, 32), PN: 3, N: 4}.Marshal()
	ct := bytes.Repeat([]byte{0xcc}, kc.MinCiphertext)
	ekPub := must(kc.X25519PublicKey(x.ekPriv))
	msgSID := bytes.Repeat([]byte{0x09}, 8)
	x3dh := func() map[string]any {
		return map[string]any{"ek": kc.Base64url(ekPub), "ik_bind_sig": kc.Base64url(x.alice.IKBindSig()),
			"ik_dh": kc.Base64url(x.alice.IKDHPub()), "ik_sig": kc.Base64url(x.alice.IKSigPub()), "opk_id": 1203, "spk_id": 7}
	}
	outerMsg := func() map[string]any {
		return map[string]any{"v": 1, "kind": "msg", "sid": kc.Base64url(msgSID), "hdr": kc.Base64url(hdr), "ct": kc.Base64url(ct)}
	}
	outerPrekey := func() map[string]any {
		o := outerMsg()
		o["kind"] = "prekey"
		o["sid"] = kc.Base64url(x.sid[:])
		o["x3dh"] = x3dh()
		return o
	}
	type outerCase struct {
		name   string
		obj    map[string]any
		raw    string // used instead of obj when set
		parses bool
		reason string
		errStr string
	}
	cases := []outerCase{}
	add := func(name string, obj map[string]any, parses bool, reason string) {
		cases = append(cases, outerCase{name: name, obj: obj, parses: parses, reason: reason})
	}
	add("msg", outerMsg(), true, "")
	o := outerPrekey()
	add("prekey_opk_present", o, true, "")
	o = outerPrekey()
	o["x3dh"].(map[string]any)["opk_id"] = nil
	add("opk_null", o, true, "")
	o = outerPrekey()
	delete(o["x3dh"].(map[string]any), "opk_id")
	add("opk_absent", o, true, "")
	o = outerMsg()
	o["x3dh"] = nil
	add("msg_x3dh_null", o, true, "")
	o = outerPrekey()
	o["sid"] = kc.Base64url(msgSID)
	add("prekey_sid_recomputed_from_ek", o, true, "")
	o = outerMsg()
	o["v"] = 2
	add("v2", o, false, "bad_envelope")
	o = outerMsg()
	o["kind"] = "other"
	add("kind_unknown", o, false, "bad_envelope")
	o = outerMsg()
	delete(o, "sid")
	add("sid_missing", o, false, "bad_envelope")
	o = outerMsg()
	o["sid"] = kc.Base64url(msgSID[:7])
	add("sid_7_bytes", o, false, "bad_envelope")
	o = outerMsg()
	o["sid"] = kc.Base64url(msgSID) + "="
	add("sid_padding_char", o, false, "bad_envelope")
	o = outerMsg()
	o["hdr"] = kc.Base64url(hdr[:40])
	add("hdr_40_bytes", o, false, "bad_envelope")
	o = outerMsg()
	h2 := dup(hdr)
	h2[0] = 0x02
	o["hdr"] = kc.Base64url(h2)
	add("hdr_version_2", o, false, "bad_envelope")
	o = outerMsg()
	o["ct"] = kc.Base64url(ct[:kc.MinCiphertext-1])
	add("ct_271_bytes", o, false, "bad_envelope")
	o = outerPrekey()
	delete(o, "x3dh")
	add("prekey_without_x3dh", o, false, "bad_envelope")
	o = outerPrekey()
	o["x3dh"].(map[string]any)["ek"] = kc.Base64url(ekPub[:31])
	add("prekey_ek_31_bytes", o, false, "bad_envelope")
	cases = append(cases, outerCase{name: "not_json", raw: "not json", parses: false, reason: "bad_envelope"})
	// Maximum size: a 40 960-byte inner padded to 41 216 plus a 16-byte tag.
	maxPadded := must(kc.Pad(bytes.Repeat([]byte{0x20}, kc.MaxInnerJSON)))
	maxCt := append(maxPadded, bytes.Repeat([]byte{0xee}, 16)...)
	var sid8 [8]byte
	copy(sid8[:], msgSID)
	maxEnv := must(kc.EncodeEnvelope(kc.KindMsg, sid8, hdr, maxCt, nil))
	cases = append(cases, outerCase{name: "max_size", raw: string(maxEnv), parses: true})

	outer := []map[string]any{}
	for _, c := range cases {
		js := c.raw
		if c.obj != nil {
			js = compactJSON(c.obj)
		}
		_, err := kc.ParseEnvelope([]byte(js))
		entry := map[string]any{"name": c.name, "json": js, "parses": c.parses}
		if c.parses {
			if err != nil {
				panic("outer " + c.name + ": " + err.Error())
			}
		} else {
			if err == nil {
				panic("outer " + c.name + " must not parse")
			}
			entry["reason"] = c.reason
			entry["error"] = kc.ErrorName(err)
		}
		outer = append(outer, entry)
	}

	// Inner round trips: the Go spellings (null optionals) and the Swift
	// spellings (absent optionals) of the same messages, plus null counters.
	roundtrip := []map[string]any{}
	addInner := func(js string) {
		m := must(kc.DecodeInner([]byte(js)))
		again := must(kc.DecodeInner(must(kc.EncodeInner(m))))
		if !reflect.DeepEqual(m, again) {
			panic("inner round trip: " + js)
		}
		roundtrip = append(roundtrip, map[string]any{"json": js})
	}
	for _, m := range inners {
		addInner(string(must(kc.EncodeInner(m))))
		var generic map[string]any
		if err := json.Unmarshal(must(kc.EncodeInner(m)), &generic); err != nil {
			panic(err)
		}
		for k, v := range generic {
			if v == nil {
				delete(generic, k)
			}
		}
		addInner(compactJSON(generic))
	}
	addInner(compactJSON(map[string]any{"t": "ctrl.capture", "id": innerID("env:blanking_null"), "ts": ts, "ttl": 0,
		"seq_from": nil, "seq_to": nil, "count": nil, "kind": "blanking_unavailable", "ref": []string{}}))

	return map[string]any{
		"padding":          padding,
		"padding_negative": paddingNeg,
		"size":             map[string]any{"max_ok_len": kc.MaxInnerJSON, "reject_len": kc.MaxInnerJSON + 1, "error": "sizeLimit"},
		"outer":            outer,
		"inner_roundtrip":  roundtrip,
	}
}

// attachmentSet is attachment.json: the blob file of a 100-byte image/jpeg
// plaintext and of an empty one, with the derived key, nonce and AAD, and the
// wrong-len negative.
func attachmentSet() map[string]any {
	type in struct {
		name    string
		blobID  []byte
		fileKey []byte
		mime    string
		pt      []byte
	}
	pt100 := make([]byte, 100)
	for i := range pt100 {
		pt100[i] = byte(i)
	}
	ins := []in{
		{"jpeg_100", kc.Hex("000102030405060708090a0b0c0d0e0f"), kc.SHA256([]byte("Kilit_vec_attachment_filekey_1")), "image/jpeg", pt100},
		{"png_empty", bytes.Repeat([]byte{0xff}, 16), kc.SHA256([]byte("Kilit_vec_attachment_filekey_2")), "image/png", []byte{}},
	}
	cases := []map[string]any{}
	var first *kc.SealedAttachment
	for _, c := range ins {
		var id [16]byte
		copy(id[:], c.blobID)
		sealed := must(kc.SealAttachment(kc.NewScriptedKeySource([][]byte{c.fileKey}), id, c.mime, c.pt))
		expectEqual("attachment open "+c.name, must(kc.OpenAttachment(c.fileKey, id, c.mime, uint64(len(c.pt)), sealed.Blob)), c.pt)
		if first == nil {
			first = sealed
		}
		cases = append(cases, map[string]any{
			"name": c.name, "blob_id": hx(c.blobID), "file_key": hx(c.fileKey), "mime": c.mime, "pt": hx(c.pt),
			"key": hx(sealed.Key), "nonce": hx(sealed.Nonce), "aad": hx(sealed.AAD), "blob": hx(sealed.Blob), "sha256": hx(sealed.SHA256[:]),
		})
	}
	var id0 [16]byte
	copy(id0[:], ins[0].blobID)
	_, err := kc.OpenAttachment(ins[0].fileKey, id0, ins[0].mime, 99, first.Blob)
	expectErr("attachment wrong_len", err, "authenticationFailure")
	return map[string]any{
		"cases": cases,
		"negative": []map[string]any{
			{"name": "wrong_len", "blob_id": hx(ins[0].blobID), "file_key": hx(ins[0].fileKey), "mime": ins[0].mime,
				"len": 99, "blob": hx(first.Blob), "error": "authenticationFailure"},
		},
	}
}
