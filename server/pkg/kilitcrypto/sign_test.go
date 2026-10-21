package kilitcrypto

import (
	"bytes"
	"errors"
	"math/big"
	"testing"
)

// RFC 8032 §7.1 test 1.
var (
	rfc8032Seed = Hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	rfc8032Pub  = Hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
	rfc8032Sig  = Hex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
)

func TestEd25519RFC8032(t *testing.T) {
	if got := Ed25519PublicKey(rfc8032Seed); !bytes.Equal(got, rfc8032Pub) {
		t.Fatalf("pub = %x", got)
	}
	if got := Sign(rfc8032Seed, nil); !bytes.Equal(got, rfc8032Sig) {
		t.Fatalf("sig = %x", got)
	}
	if err := Verify(rfc8032Pub, nil, rfc8032Sig); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if err := Verify(rfc8032Pub, []byte("x"), rfc8032Sig); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("wrong msg: %v", err)
	}
}

func TestEd25519StrictNegatives(t *testing.T) {
	withS := func(s []byte) []byte { return Concat(rfc8032Sig[:32], s) }
	withR := func(r []byte) []byte { return Concat(r, rfc8032Sig[32:]) }
	// S' = S + L is accepted by a lax verifier; the bytewise rule rejects it.
	sPlusL := new(big.Int).Add(leBig(rfc8032Sig[32:]), leBig(Ed25519L))
	sLow := append([]byte(nil), Ed25519L...)
	sLow[0]-- // L − 1 (< L) but a wrong scalar: must fail in the library verify, not the pre-check
	cases := []struct {
		name string
		pub  []byte
		sig  []byte
		err  error
	}{
		{"sig_63", rfc8032Pub, rfc8032Sig[:63], ErrBadSignature},
		{"sig_65", rfc8032Pub, append(append([]byte(nil), rfc8032Sig...), 0), ErrBadSignature},
		{"s_eq_l", rfc8032Pub, withS(Ed25519L), ErrBadSignature},
		{"s_plus_l", rfc8032Pub, withS(leBytes(sPlusL)), ErrBadSignature},
		{"s_top_bit", rfc8032Pub, withS(Concat(rfc8032Sig[32:63], []byte{0x90})), ErrBadSignature},
		{"s_l_minus_1", rfc8032Pub, withS(sLow), ErrBadSignature},
		{"pub_31", rfc8032Pub[:31], rfc8032Sig, ErrBadKeyLength},
		{"pub_33", append(append([]byte(nil), rfc8032Pub...), 0), rfc8032Sig, ErrBadKeyLength},
	}
	for i, p := range SmallOrderPoints {
		cases = append(cases,
			struct {
				name string
				pub  []byte
				sig  []byte
				err  error
			}{"small_order_A_" + string(rune('a'+i)), p, rfc8032Sig, ErrBadSignature},
			struct {
				name string
				pub  []byte
				sig  []byte
				err  error
			}{"small_order_R_" + string(rune('a'+i)), rfc8032Pub, withR(p), ErrBadSignature})
	}
	for _, c := range cases {
		if err := Verify(c.pub, nil, c.sig); !errors.Is(err, c.err) {
			t.Errorf("%s: err = %v, want %v", c.name, err, c.err)
		}
	}
	for _, p := range SmallOrderPoints {
		if err := CheckEd25519PublicKey(p); !errors.Is(err, ErrBadPublicKey) {
			t.Errorf("CheckEd25519PublicKey(%x) = %v", p, err)
		}
	}
	if err := CheckEd25519PublicKey(rfc8032Pub[:31]); !errors.Is(err, ErrBadKeyLength) {
		t.Error("31-byte public key")
	}
	if err := CheckEd25519PublicKey(rfc8032Pub); err != nil {
		t.Error("good key rejected")
	}
}

func TestScalarLessThanL(t *testing.T) {
	if !scalarLessThanL(rfc8032Sig[32:]) {
		t.Error("valid S must be < L")
	}
	if scalarLessThanL(Ed25519L) {
		t.Error("S == L must be rejected")
	}
	one := make([]byte, 32)
	one[0] = 1
	if !scalarLessThanL(one) {
		t.Error("1 < L")
	}
	lPlus1 := append([]byte(nil), Ed25519L...)
	lPlus1[0] = 0xee // indices 31..1 tie, index 0 decides
	if scalarLessThanL(lPlus1) {
		t.Error("L + 1 must be rejected")
	}
	lMinus1 := append([]byte(nil), Ed25519L...)
	lMinus1[0] = 0xec
	if !scalarLessThanL(lMinus1) {
		t.Error("L − 1 is < L")
	}
	top := make([]byte, 32)
	top[31] = 0x11 // index 31 alone decides
	if scalarLessThanL(top) {
		t.Error("0x11… must be rejected")
	}
}

// --- Small-order table derivation -----------------------------------------
//
// The 14 encodings are libsodium's 7-entry ed25519_blacklist (ge25519_has_small_order
// masks bit 255, so each entry stands for both sign bits). Below they are
// re-derived: every decodable entry is decoded as an Edwards point and
// multiplied by 8, which must give the identity; the non-canonical entries
// (y ≥ p) are shown to be the y = 0 and y = 1 points under a lax decoder.

var (
	edP = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	edD = func() *big.Int {
		n := big.NewInt(-121665)
		inv := new(big.Int).ModInverse(big.NewInt(121666), edP)
		return new(big.Int).Mod(new(big.Int).Mul(n, inv), edP)
	}()
	edI = new(big.Int).Exp(big.NewInt(2), new(big.Int).Div(new(big.Int).Sub(edP, big.NewInt(1)), big.NewInt(4)), edP)
)

func leBig(b []byte) *big.Int {
	r := make([]byte, len(b))
	for i := range b {
		r[len(b)-1-i] = b[i]
	}
	return new(big.Int).SetBytes(r)
}

func leBytes(v *big.Int) []byte {
	b := v.FillBytes(make([]byte, 32))
	for i, j := 0, 31; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return b
}

type edPoint struct{ x, y *big.Int }

func modP(v *big.Int) *big.Int { return new(big.Int).Mod(v, edP) }

// edDecode is the RFC 8032 §5.1.3 decoding (strict: y < p).
func edDecode(enc []byte) (edPoint, bool) {
	y := leBig(enc)
	sign := y.Bit(255)
	y.SetBit(y, 255, 0)
	if y.Cmp(edP) >= 0 {
		return edPoint{}, false
	}
	y2 := modP(new(big.Int).Mul(y, y))
	u := modP(new(big.Int).Sub(y2, big.NewInt(1)))
	v := modP(new(big.Int).Add(new(big.Int).Mul(edD, y2), big.NewInt(1)))
	uv := modP(new(big.Int).Mul(u, new(big.Int).ModInverse(v, edP)))
	exp := new(big.Int).Div(new(big.Int).Add(edP, big.NewInt(3)), big.NewInt(8))
	x := new(big.Int).Exp(uv, exp, edP)
	if modP(new(big.Int).Sub(new(big.Int).Mul(v, new(big.Int).Mul(x, x)), u)).Sign() != 0 {
		x = modP(new(big.Int).Mul(x, edI))
		if modP(new(big.Int).Sub(new(big.Int).Mul(v, new(big.Int).Mul(x, x)), u)).Sign() != 0 {
			return edPoint{}, false
		}
	}
	if x.Sign() == 0 && sign == 1 {
		return edPoint{}, false
	}
	if x.Bit(0) != sign {
		x = modP(new(big.Int).Neg(x))
	}
	return edPoint{x, y}, true
}

func edAdd(a, b edPoint) edPoint {
	x1y2 := new(big.Int).Mul(a.x, b.y)
	x2y1 := new(big.Int).Mul(b.x, a.y)
	y1y2 := new(big.Int).Mul(a.y, b.y)
	x1x2 := new(big.Int).Mul(a.x, b.x)
	dxxyy := modP(new(big.Int).Mul(edD, new(big.Int).Mul(x1x2, y1y2)))
	x3 := modP(new(big.Int).Mul(new(big.Int).Add(x1y2, x2y1), new(big.Int).ModInverse(modP(new(big.Int).Add(big.NewInt(1), dxxyy)), edP)))
	y3 := modP(new(big.Int).Mul(new(big.Int).Add(y1y2, x1x2), new(big.Int).ModInverse(modP(new(big.Int).Sub(big.NewInt(1), dxxyy)), edP)))
	return edPoint{x3, y3}
}

func edIsIdentity(p edPoint) bool { return p.x.Sign() == 0 && p.y.Cmp(big.NewInt(1)) == 0 }

func TestSmallOrderTableByPointArithmetic(t *testing.T) {
	decodable := 0
	for _, enc := range SmallOrderPoints {
		p, ok := edDecode(enc)
		if !ok {
			// Non-canonical: with bit 255 masked, y must be ≥ p (p, p+1) or the
			// encoding is the x = 0, sign = 1 impossibility of y = 1 / y = p − 1.
			y := leBig(enc)
			y.SetBit(y, 255, 0)
			if y.Cmp(edP) < 0 && !(y.Cmp(big.NewInt(1)) == 0 || y.Cmp(new(big.Int).Sub(edP, big.NewInt(1))) == 0) {
				t.Errorf("%x: undecodable for an unexpected reason", enc)
			}
			continue
		}
		decodable++
		q := p
		for i := 0; i < 3; i++ {
			q = edAdd(q, q)
		}
		if !edIsIdentity(q) {
			t.Errorf("%x: 8·P is not the identity", enc)
		}
	}
	if decodable != 8 {
		t.Errorf("decodable entries = %d, want 8", decodable)
	}
	// The order-8 points are the only ones with x² = −y², i.e. d·y⁴ + 2y² − 1 = 0.
	for _, enc := range SmallOrderPoints[4:8] {
		p, _ := edDecode(enc)
		y2 := modP(new(big.Int).Mul(p.y, p.y))
		v := modP(new(big.Int).Add(new(big.Int).Mul(edD, new(big.Int).Mul(y2, y2)), new(big.Int).Sub(new(big.Int).Mul(big.NewInt(2), y2), big.NewInt(1))))
		if v.Sign() != 0 {
			t.Errorf("%x: not an order-8 point", enc)
		}
	}
}

// TestSmallOrderTableMatchesLibsodium pins the 7 libsodium blacklist entries
// (crypto_core/ed25519/ref10/ed25519_ref10.c) and checks the table is exactly
// their expansion over both sign bits.
func TestSmallOrderTableMatchesLibsodium(t *testing.T) {
	libsodium := []string{
		"0000000000000000000000000000000000000000000000000000000000000000",
		"0100000000000000000000000000000000000000000000000000000000000000",
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	}
	for i, h := range libsodium {
		base := Hex(h)
		flipped := append([]byte(nil), base...)
		flipped[31] |= 0x80
		if !bytes.Equal(SmallOrderPoints[2*i], base) || !bytes.Equal(SmallOrderPoints[2*i+1], flipped) {
			t.Errorf("entry %d does not expand libsodium's %s", i, h)
		}
	}
	if !IsSmallOrder(SmallOrderPoints[5]) || IsSmallOrder(rfc8032Pub) {
		t.Error("IsSmallOrder")
	}
}

func TestSignedMessageLayouts(t *testing.T) {
	dh := bytes.Repeat([]byte{0xaa}, 32)
	spk := bytes.Repeat([]byte{0xbb}, 32)
	nonce := bytes.Repeat([]byte{0x20}, 32)
	if got := IKBindMessage(dh); !bytes.Equal(got, Concat([]byte("Kilit_IKBind_v1"), dh)) {
		t.Errorf("IKBind = %x", got)
	}
	if got := SPKMessage(7, 1759900000, spk); !bytes.Equal(got, Concat([]byte("Kilit_SPK_v1"), Hex("00000007"), Hex("0000000068e5f160"), spk)) {
		t.Errorf("SPK = %x", got)
	}
	o1, o2 := bytes.Repeat([]byte{0x01}, 32), bytes.Repeat([]byte{0x02}, 32)
	want := Concat([]byte("Kilit_OPKBatch_v1"), Hex("00000002"), Hex("000004b3"), o1, Hex("000004b4"), o2)
	if got := OPKBatchMessage([]OPK{{1203, o1}, {1204, o2}}); !bytes.Equal(got, want) {
		t.Errorf("OPKBatch = %x", got)
	}
	if got := OPKBatchMessage(nil); !bytes.Equal(got, Concat([]byte("Kilit_OPKBatch_v1"), Hex("00000000"))) {
		t.Errorf("empty batch = %x", got)
	}
	dev := "6f1d2c3b-4a59-4e8f-9b0c-1d2e3f4a5b6c"
	origin := "https://kilit.example.com"
	ts := Hex("0000000068e77800")
	z := []byte{0}
	if got := RegisterMessage("alice", dh, dev, nonce, 1760000000, origin); !bytes.Equal(got,
		Concat([]byte("Kilit_Register_v1"), z, []byte("alice"), z, dh, z, []byte(dev), z, nonce, z, ts, z, []byte(origin))) {
		t.Errorf("Register = %x", got)
	}
	if got := LoginMessage("alice", nonce, 1760000000, dev, origin); !bytes.Equal(got,
		Concat([]byte("Kilit_Auth_v1"), z, []byte("alice"), z, nonce, z, ts, z, []byte(dev), z, []byte(origin))) {
		t.Errorf("Login = %x", got)
	}
	if got := DeleteMessage("alice", nonce, 1760000000, origin); !bytes.Equal(got,
		Concat([]byte("Kilit_Delete_v1"), z, []byte("alice"), z, nonce, z, ts, z, []byte(origin))) {
		t.Errorf("Delete = %x", got)
	}
	// Signatures over these layouts verify with the matching public key.
	seed := bytes.Repeat([]byte{0x01}, 32)
	msg := RegisterMessage("alice", dh, dev, nonce, 1760000000, origin)
	if err := Verify(Ed25519PublicKey(seed), msg, Sign(seed, msg)); err != nil {
		t.Errorf("verify register proof: %v", err)
	}
}
