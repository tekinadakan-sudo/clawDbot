package gen

import (
	"bytes"

	kc "github.com/tekinadakan-sudo/clawDbot/server/pkg/kilitcrypto"
)

// primitives is primitives.json: RFC 7748 §6.1, RFC 8032 §7.1, RFC 5869
// A.1, RFC 8439 §2.8.2, the empty-vs-zero-salt proof and the strict-Ed25519
// negatives with the small-order table. Every RFC constant is re-derived by
// the reference implementation before it is emitted.
func primitives() map[string]any {
	// RFC 7748 §6.1
	aPriv := kc.Hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
	aPub := kc.Hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
	bPriv := kc.Hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
	bPub := kc.Hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
	shared := kc.Hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
	expectEqual("rfc7748 alice pub", must(kc.X25519PublicKey(aPriv)), aPub)
	expectEqual("rfc7748 bob pub", must(kc.X25519PublicKey(bPriv)), bPub)
	expectEqual("rfc7748 shared a", must(kc.X25519(aPriv, bPub)), shared)
	expectEqual("rfc7748 shared b", must(kc.X25519(bPriv, aPub)), shared)
	x25519 := []map[string]any{
		{"name": "rfc7748", "priv": hx(aPriv), "pub": hx(aPub), "peer_pub": hx(bPub), "shared": hx(shared)},
		{"name": "rfc7748_bob", "priv": hx(bPriv), "pub": hx(bPub), "peer_pub": hx(aPub), "shared": hx(shared)},
	}
	zero32 := make([]byte, 32)
	one32 := seedKey(1, 0)
	_, err := kc.X25519(aPriv, zero32)
	expectErr("x25519 low order 0", err, "lowOrderPoint")
	_, err = kc.X25519(aPriv, one32)
	expectErr("x25519 low order 1", err, "lowOrderPoint")
	_, err = kc.X25519(aPriv, bPub[:31])
	expectErr("x25519 short key", err, "badKeyLength")
	x25519Neg := []map[string]any{
		{"name": "low_order", "priv": hx(aPriv), "peer_pub": hx(zero32), "error": "lowOrderPoint"},
		{"name": "low_order_one", "priv": hx(aPriv), "peer_pub": hx(one32), "error": "lowOrderPoint"},
		{"name": "short_key", "priv": hx(aPriv), "peer_pub": hx(bPub[:31]), "error": "badKeyLength"},
	}

	// RFC 8032 §7.1 tests 1 and 2 (Go's signatures are the RFC's: deterministic).
	type edCase struct{ name, seed, pub, msg, sig string }
	edCases := []edCase{
		{"rfc8032_1", "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
			"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
			"e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"},
		{"rfc8032_2", "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
			"3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
			"92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"},
	}
	ed := []map[string]any{}
	for _, c := range edCases {
		seed, pub, msg, sig := kc.Hex(c.seed), kc.Hex(c.pub), kc.Hex(c.msg), kc.Hex(c.sig)
		expectEqual(c.name+" pub", kc.Ed25519PublicKey(seed), pub)
		expectEqual(c.name+" sig", kc.Sign(seed, msg), sig)
		if err := kc.Verify(pub, msg, sig); err != nil {
			panic(c.name + ": " + err.Error())
		}
		ed = append(ed, map[string]any{"name": c.name, "seed": hx(seed), "pub": hx(pub), "msg": hx(msg), "go_sig": hx(sig)})
	}
	pub2, msg2, sig2 := kc.Hex(edCases[1].pub), kc.Hex(edCases[1].msg), kc.Hex(edCases[1].sig)
	sEqL := append(dup(sig2[:32]), kc.Ed25519L...)
	sBig := append(dup(sig2[:32]), bytes.Repeat([]byte{0xff}, 32)...)
	rSmall := append(dup(kc.SmallOrderPoints[2]), sig2[32:]...)
	flipped := dup(msg2)
	flipped[0] ^= 1
	edNeg := []map[string]any{
		{"name": "s_eq_l", "pub": hx(pub2), "msg": hx(msg2), "sig": hx(sEqL), "error": "badSignature"},
		{"name": "s_ge_l", "pub": hx(pub2), "msg": hx(msg2), "sig": hx(sBig), "error": "badSignature"},
		{"name": "sig_len_63", "pub": hx(pub2), "msg": hx(msg2), "sig": hx(sig2[:63]), "error": "badSignature"},
		{"name": "small_order_pub", "pub": hx(kc.SmallOrderPoints[2]), "msg": hx(msg2), "sig": hx(sig2), "error": "badSignature"},
		{"name": "small_order_r", "pub": hx(pub2), "msg": hx(msg2), "sig": hx(rSmall), "error": "badSignature"},
		{"name": "wrong_message", "pub": hx(pub2), "msg": hx(flipped), "sig": hx(sig2), "error": "badSignature"},
		{"name": "pub_len_31", "pub": hx(pub2[:31]), "msg": hx(msg2), "sig": hx(sig2), "error": "badKeyLength"},
	}
	for _, n := range edNeg {
		expectErr("ed25519 "+n["name"].(string), kc.Verify(kc.Hex(n["pub"].(string)), kc.Hex(n["msg"].(string)), kc.Hex(n["sig"].(string))), n["error"].(string))
	}
	smallOrder := make([]string, 0, 14)
	for _, p := range kc.SmallOrderPoints {
		expectErr("small order import", kc.CheckEd25519PublicKey(p), "badPublicKey")
		smallOrder = append(smallOrder, hx(p))
	}

	// RFC 5869 A.1
	ikm := bytes.Repeat([]byte{0x0b}, 22)
	salt := kc.Hex("000102030405060708090a0b0c")
	info := kc.Hex("f0f1f2f3f4f5f6f7f8f9")
	okm := kc.Hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
	expectEqual("rfc5869 1", kc.HKDF(ikm, salt, info, 42), okm)
	info2 := []byte(kc.InfoX3DH)
	okmEmpty := kc.HKDF(ikm, nil, info2, 32)
	expectEqual("empty vs zero salt", kc.HKDF(ikm, kc.Zeros, info2, 32), okmEmpty)
	hkdf := []map[string]any{
		{"name": "rfc5869_1", "ikm": hx(ikm), "salt": hx(salt), "info": hx(info), "len": 42, "okm": hx(okm)},
		{"name": "empty_vs_zero_salt", "ikm": hx(ikm), "salt_a": "", "salt_b": hx(kc.Zeros), "info": hx(info2), "len": 32, "okm": hx(okmEmpty)},
	}

	// KDF_CK on two chain keys.
	ckCases := []map[string]any{}
	for _, ck := range [][]byte{bytes.Repeat([]byte{0x42}, 32), kc.SHA256([]byte("Kilit_vec_ck"))} {
		mk, next := kc.KDFCK(ck)
		ckCases = append(ckCases, map[string]any{"ck": hx(ck), "mk": hx(mk), "ck_next": hx(next)})
	}

	// RFC 8439 §2.8.2
	key := kc.Hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
	nonce := kc.Hex("070000004041424344454647")
	aad := kc.Hex("50515253c0c1c2c3c4c5c6c7")
	pt := []byte("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.")
	wire := kc.Hex("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116" +
		"1ae10b594f09e26a7e902ecbd0600691")
	expectEqual("rfc8439 seal", must(kc.Seal(key, nonce, aad, pt)), wire)
	expectEqual("rfc8439 open", must(kc.Open(key, nonce, aad, wire)), pt)
	badTag := dup(wire)
	badTag[len(badTag)-1] ^= 1
	_, err = kc.Seal(key[:31], nonce, nil, nil)
	expectErr("chachapoly short key", err, "incorrectKeySize")
	_, err = kc.Open(key, nonce, aad, badTag)
	expectErr("chachapoly bad tag", err, "authenticationFailure")

	return map[string]any{
		"x25519":                     x25519,
		"x25519_negative":            x25519Neg,
		"ed25519":                    ed,
		"ed25519_negative":           edNeg,
		"ed25519_small_order_points": smallOrder,
		"hkdf":                       hkdf,
		"hmac_kdf_ck":                ckCases,
		"chachapoly": []map[string]any{
			{"name": "rfc8439", "key": hx(key), "nonce": hx(nonce), "aad": hx(aad), "pt": hx(pt), "wire": hx(wire)},
		},
		"chachapoly_negative": []map[string]any{
			{"name": "short_key", "key": hx(key[:31]), "error": "incorrectKeySize"},
			{"name": "bad_tag", "key": hx(key), "nonce": hx(nonce), "aad": hx(aad), "wire": hx(badTag), "error": "authenticationFailure"},
		},
	}
}

// base64urlSet is base64url.json: inputs of every length mod 3, bytes ≥ 0x80,
// an 8-byte sid (11 characters), and one negative per strict rule of §3.
func base64urlSet() map[string]any {
	all := make([]byte, 256)
	for i := range all {
		all[i] = byte(i)
	}
	inputs := [][]byte{
		{}, {0x00}, {0xff}, {0xff, 0xfe}, {0xfb, 0xff, 0xbf}, {0x00, 0x01, 0x02, 0x03},
		{0xde, 0xad, 0xbe, 0xef, 0x00}, bytes.Repeat([]byte{0xab}, 8), bytes.Repeat([]byte{0xff}, 32), all,
	}
	cases := []map[string]any{}
	for _, b := range inputs {
		text := kc.Base64url(b)
		expectEqual("base64url round trip", must(kc.Base64urlDecode(text)), b)
		cases = append(cases, map[string]any{"bytes": hx(b), "text": text})
	}
	negative := []map[string]any{
		{"name": "padding", "text": "AQ==", "error": "bad_envelope"},
		{"name": "alphabet", "text": "AQ+/", "error": "bad_envelope"},
		{"name": "length_mod4_1", "text": "AQIDB", "error": "bad_envelope"},
		{"name": "trailing_bits", "text": "AR", "error": "bad_envelope"},
	}
	for _, n := range negative {
		_, err := kc.Base64urlDecode(n["text"].(string))
		expectErr("base64url "+n["name"].(string), err, "bad_envelope")
	}
	return map[string]any{"cases": cases, "negative": negative}
}
