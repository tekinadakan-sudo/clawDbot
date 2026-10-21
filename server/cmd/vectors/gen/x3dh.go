package gen

import (
	"bytes"
	"encoding/json"

	kc "github.com/tekinadakan-sudo/clawDbot/server/pkg/kilitcrypto"
)

// Fixed inputs of §3.8 Set A.
const (
	t0           = int64(1760000000) // ts and every scenario's clock_start
	spkCreatedAt = int64(1759900000)
	deviceID     = "6f1d2c3b-4a59-4e8f-9b0c-1d2e3f4a5b6c"
	serverOrigin = "https://kilit.example.com"
	wmUnix       = int64(1760400000)
)

// setA holds the Set A material shared by every other set.
type setA struct {
	alice, bob kc.Identity
	ekPriv     []byte // Alice's EK (first entry of A's key_sources)
	dhsPriv    []byte // Alice's first DHs (second entry)
	bobSPKPriv []byte
	bobOPKs    [][]byte // 1203, 1204
	aliceSPK   []byte
	aliceOPKs  [][]byte // 2301, 2302
	nonce      []byte
	bundle     kc.Bundle // Bob's, with OPK 1203
	sk, ws, ad []byte
	sid        [8]byte
	doc        map[string]any
}

func (x *setA) alicePeer() kc.PeerIdentity {
	return kc.PeerIdentity{Username: "alice", IKSig: x.alice.IKSigPub(), IKDH: x.alice.IKDHPub()}
}

func (x *setA) bobPeer() kc.PeerIdentity {
	return kc.PeerIdentity{Username: "bob", IKSig: x.bob.IKSigPub(), IKDH: x.bob.IKDHPub()}
}

// buildSetA derives x3dh_session.json and the shared values.
func buildSetA() *setA {
	x := &setA{
		alice:      kc.Identity{Username: "alice", IKSigSeed: seedKey(0, 1), IKDHPriv: seedKey(0, 2)},
		bob:        kc.Identity{Username: "bob", IKSigSeed: seedKey(0x10, 1), IKDHPriv: seedKey(0x10, 2)},
		ekPriv:     seedKey(0, 3),
		dhsPriv:    seedKey(0, 4),
		bobSPKPriv: seedKey(0x10, 3),
		bobOPKs:    [][]byte{seedKey(0x10, 4), seedKey(0x10, 6)},
		aliceSPK:   seedKey(0, 7),
		aliceOPKs:  [][]byte{seedKey(0, 8), seedKey(0, 9)},
		nonce:      bytes.Repeat([]byte{0x20}, 32),
	}
	spkPub := must(kc.X25519PublicKey(x.bobSPKPriv))
	opkPubs := []kc.OPK{
		{ID: 1203, Pub: must(kc.X25519PublicKey(x.bobOPKs[0]))},
		{ID: 1204, Pub: must(kc.X25519PublicKey(x.bobOPKs[1]))},
	}
	opkID := uint32(1203)
	x.bundle = kc.Bundle{
		Username: "bob", IKSig: x.bob.IKSigPub(), IKDH: x.bob.IKDHPub(), IKBindSig: x.bob.IKBindSig(),
		SPKID: 7, SPKPub: spkPub, SPKCreatedAt: uint64(spkCreatedAt),
		SPKSig: kc.Sign(x.bob.IKSigSeed, kc.SPKMessage(7, uint64(spkCreatedAt), spkPub)),
		OPKID:  &opkID, OPKPub: opkPubs[0].Pub,
	}

	// Initiator and responder must agree, with and without the OPK.
	res := must(kc.Initiate(x.alice, x.bundle, nil, t0, kc.NewScriptedKeySource([][]byte{x.ekPriv})))
	resp := must(kc.Respond(x.bob, x.alicePeer(), x.alice.IKBindSig(), res.EKPub, x.bobSPKPriv, x.bobOPKs[0]))
	expectEqual("x3dh sk", resp.SK, res.SK)
	expectEqual("x3dh ad", resp.AD, res.AD)
	expectEqual("x3dh ws", resp.WS, res.WS)
	if resp.SID != res.SID {
		panic("x3dh sid")
	}
	noOPK := x.bundle
	noOPK.OPKID, noOPK.OPKPub = nil, nil
	res2 := must(kc.Initiate(x.alice, noOPK, nil, t0, kc.NewScriptedKeySource([][]byte{x.ekPriv})))
	resp2 := must(kc.Respond(x.bob, x.alicePeer(), x.alice.IKBindSig(), res2.EKPub, x.bobSPKPriv, nil))
	expectEqual("x3dh sk no opk", resp2.SK, res2.SK)
	expectEqual("x3dh ad no opk", res2.AD, res.AD)
	x.sk, x.ws, x.ad, x.sid = res.SK, res.WS, res.AD, res.SID

	// Signatures (Go deterministic; Swift verifies).
	sig := func(signer string, seed, msg []byte) map[string]any {
		s := kc.Sign(seed, msg)
		pub := kc.Ed25519PublicKey(seed)
		if err := kc.Verify(pub, msg, s); err != nil {
			panic(err)
		}
		return map[string]any{"signer": signer, "msg": hx(msg), "sig": hx(s)}
	}
	signatures := map[string]any{
		"ik_bind_sig":    sig("bob", x.bob.IKSigSeed, kc.IKBindMessage(x.bob.IKDHPub())),
		"spk_sig":        sig("bob", x.bob.IKSigSeed, kc.SPKMessage(7, uint64(spkCreatedAt), spkPub)),
		"opks_sig":       sig("bob", x.bob.IKSigSeed, kc.OPKBatchMessage(opkPubs)),
		"register_proof": sig("alice", x.alice.IKSigSeed, kc.RegisterMessage("alice", x.alice.IKDHPub(), deviceID, x.nonce, uint64(t0), serverOrigin)),
		"login_sig":      sig("alice", x.alice.IKSigSeed, kc.LoginMessage("alice", x.nonce, uint64(t0), deviceID, serverOrigin)),
		"delete_sig":     sig("alice", x.alice.IKSigSeed, kc.DeleteMessage("alice", x.nonce, uint64(t0), serverOrigin)),
	}
	if !kc.ValidDeviceID(deviceID) {
		panic("device id")
	}

	// The first prekey envelope, produced by the app-level send path.
	srv := kc.NewMemServer()
	bobDev := kc.NewDevice(x.bob, kc.RandomKeySource{}, srv)
	bobDev.AddSPK(7, x.bobSPKPriv, spkCreatedAt)
	bobDev.AddOPK(1203, x.bobOPKs[0], t0)
	bobDev.AddOPK(1204, x.bobOPKs[1], t0)
	b, opks := bobDev.Publish()
	srv.Register(b, opks)
	aliceDev := kc.NewDevice(x.alice, kc.NewScriptedKeySource([][]byte{x.ekPriv, x.dhsPriv}), srv)
	out, _, err := aliceDev.Send("bob", textInner(innerID("x3dh:first"), "merhaba", t0), t0)
	if err != nil {
		panic(err)
	}
	if out.SID != x.sid || out.Kind != kc.KindPrekey {
		panic("first envelope sid/kind")
	}
	parsed := must(kc.ParseEnvelope(out.Envelope))
	if parsed.SID != x.sid || *parsed.X3DH.OPKID != 1203 || parsed.X3DH.SPKID != 7 {
		panic("first envelope parse")
	}

	// Negative cases of §3.8, each reproduced here.
	other := kc.Identity{Username: "alice", IKSigSeed: seedKey(0x40, 1), IKDHPriv: seedKey(0x40, 2)}
	known := x.alicePeer()
	swapped := known
	swapped.IKDH = other.IKDHPub()
	expectErr("ik_dh_swapped", kc.CheckIdentity(known, swapped), "identityMismatch")
	badBind := kc.Sign(x.alice.IKSigSeed, kc.IKBindMessage(other.IKDHPub()))
	_, err = kc.Respond(x.bob, known, badBind, res.EKPub, x.bobSPKPriv, nil)
	expectErr("bad_bind_sig", err, "badSignature")
	staleAt := uint64(t0 - 22*86400)
	stale := x.bundle
	stale.SPKCreatedAt = staleAt
	stale.SPKSig = kc.Sign(x.bob.IKSigSeed, kc.SPKMessage(7, staleAt, spkPub))
	_, err = kc.Initiate(x.alice, stale, nil, t0, kc.NewScriptedKeySource([][]byte{x.ekPriv}))
	expectErr("stale_spk", err, "staleSPK")

	x.doc = map[string]any{
		"inputs": map[string]any{
			"alice": map[string]any{"username": "alice", "ik_sig_seed": hx(x.alice.IKSigSeed), "ik_dh_priv": hx(x.alice.IKDHPriv),
				"ek_priv": hx(x.ekPriv), "dhs_priv": hx(x.dhsPriv)},
			"bob": map[string]any{"username": "bob", "ik_sig_seed": hx(x.bob.IKSigSeed), "ik_dh_priv": hx(x.bob.IKDHPriv),
				"spk_priv": hx(x.bobSPKPriv), "spk_id": 7, "spk_created_at": spkCreatedAt,
				"opks": []map[string]any{{"id": 1203, "priv": hx(x.bobOPKs[0])}, {"id": 1204, "priv": hx(x.bobOPKs[1])}}},
			"device_id": deviceID, "nonce": hx(x.nonce), "ts": t0, "server_origin": serverOrigin,
		},
		"public": map[string]any{
			"alice": map[string]any{"ik_sig": hx(x.alice.IKSigPub()), "ik_dh": hx(x.alice.IKDHPub()), "ek": hx(res.EKPub)},
			"bob": map[string]any{"ik_sig": hx(x.bob.IKSigPub()), "ik_dh": hx(x.bob.IKDHPub()), "spk": hx(spkPub),
				"opks": []map[string]any{{"id": 1203, "pub": hx(opkPubs[0].Pub)}, {"id": 1204, "pub": hx(opkPubs[1].Pub)}}},
		},
		"signatures": signatures,
		"x3dh": map[string]any{
			"dh1": hx(res.DH1), "dh2": hx(res.DH2), "dh3": hx(res.DH3), "dh4": hx(res.DH4),
			"sk": hx(res.SK), "sk_no_opk": hx(res2.SK), "ws": hx(res.WS), "sid": hx(res.SID[:]), "ad": hx(res.AD),
		},
		"first_envelope": json.RawMessage(out.Envelope),
		"negative": []map[string]any{
			{"name": "ik_dh_swapped", "error": "identityMismatch"},
			{"name": "bad_bind_sig", "error": "badSignature"},
			{"name": "stale_spk", "spk_created_at": staleAt, "error": "staleSPK"},
		},
	}
	return x
}

// safetySet is safety.json for the Set A identities.
func safetySet(x *setA) map[string]any {
	a, b := x.alicePeer(), x.bobPeer()
	number := kc.SafetyNumber(a, b)
	if kc.SafetyNumber(b, a) != number || len(number) != 60 {
		panic("safety number")
	}
	return map[string]any{
		"cases": []map[string]any{
			{"username": "alice", "ik_sig": hx(a.IKSig), "ik_dh": hx(a.IKDH), "digits": kc.SafetyDigits("alice", a.IKSig, a.IKDH)},
			{"username": "bob", "ik_sig": hx(b.IKSig), "ik_dh": hx(b.IKDH), "digits": kc.SafetyDigits("bob", b.IKSig, b.IKDH)},
		},
		"pairs": []map[string]any{
			{"a": "alice", "b": "bob", "number": number, "qr": kc.SafetyQR(number)},
		},
	}
}

// watermarkSet is watermark.json for Set A's ws viewed by alice at wmUnix.
func watermarkSet(x *setA) map[string]any {
	p := kc.NewWatermarkPayload(x.ws, "alice", wmUnix)
	crc, steps := kc.CRC4(p.Tag, p.Day)
	if crc != p.CRC || p.Day != 7 {
		panic("watermark crc/day")
	}
	cells := make([][]bool, 6)
	for r := range cells {
		cells[r] = p.Cells[r][:]
	}
	toBytes := func(m []int8) []byte {
		out := make([]byte, len(m))
		for i, v := range m {
			out[i] = byte(v)
		}
		return out
	}
	map1, map2, map3 := p.DeltaMap(1), p.DeltaMap(2), p.DeltaMap(3)
	samples := []map[string]any{}
	for i := 0; i < 16; i++ {
		sx, sy := (i*131+7)%504, (i*97+11)%504
		d := map3[sy*504+sx]
		l, dk := kc.LighterDarker(d)
		samples = append(samples, map[string]any{"x": sx, "y": sy, "delta": d, "lighter": l, "darker": dk})
	}
	return map[string]any{
		"inputs":    map[string]any{"ws": hx(x.ws), "viewer": "alice", "unix": wmUnix},
		"tag":       p.Tag,
		"day":       p.Day,
		"crc_steps": steps,
		"crc":       p.CRC,
		"payload16": p.Payload,
		"sync":      kc.WMSyncBits,
		"cells":     cells,
		"delta": map[string]any{
			"cell_pt": kc.WMCellPt, "k_per_scale": kc.WMKPerScale, "amplitude": kc.WMAmplitude,
			"scale1":         map[string]any{"w": 168, "h": 168, "int8": hx(toBytes(map1))},
			"scale2_sha256":  hx(kc.SHA256(toBytes(map2))),
			"scale3_sha256":  hx(kc.SHA256(toBytes(map3))),
			"samples_scale3": samples,
		},
	}
}
