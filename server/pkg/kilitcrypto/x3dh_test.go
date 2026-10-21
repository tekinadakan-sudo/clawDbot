package kilitcrypto

import (
	"bytes"
	"errors"
	"testing"
)

// Set A inputs of §3.8.
func seedKey(prefix byte, last byte) []byte {
	b := make([]byte, 32)
	b[0] = prefix
	b[31] = last
	return b
}

const (
	setATS        = int64(1760000000)
	setASPKCreate = uint64(1759900000)
)

func setAAlice() Identity {
	return Identity{Username: "alice", IKSigSeed: seedKey(0, 1), IKDHPriv: seedKey(0, 2)}
}

func setABob() Identity {
	return Identity{Username: "bob", IKSigSeed: seedKey(0x10, 1), IKDHPriv: seedKey(0x10, 2)}
}

// setABobBundle builds Bob's published bundle; withOPK selects OPK 1203.
func setABobBundle(t *testing.T, withOPK bool) (Bundle, []byte, []byte) {
	t.Helper()
	bob := setABob()
	spkPriv := seedKey(0x10, 3)
	spkPub, _ := X25519PublicKey(spkPriv)
	b := Bundle{
		Username: "bob", IKSig: bob.IKSigPub(), IKDH: bob.IKDHPub(), IKBindSig: bob.IKBindSig(),
		SPKID: 7, SPKPub: spkPub, SPKCreatedAt: setASPKCreate,
		SPKSig: Sign(bob.IKSigSeed, SPKMessage(7, setASPKCreate, spkPub)),
	}
	var opkPriv []byte
	if withOPK {
		opkPriv = seedKey(0x10, 4)
		b.OPKPub, _ = X25519PublicKey(opkPriv)
		id := uint32(1203)
		b.OPKID = &id
	}
	return b, spkPriv, opkPriv
}

func TestX3DHSymmetry(t *testing.T) {
	for _, withOPK := range []bool{true, false} {
		alice, bob := setAAlice(), setABob()
		bundle, spkPriv, opkPriv := setABobBundle(t, withOPK)
		ks := NewScriptedKeySource([][]byte{seedKey(0, 3), seedKey(0, 4)})
		a, err := Initiate(alice, bundle, nil, setATS, ks)
		if err != nil {
			t.Fatalf("initiate(opk=%v): %v", withOPK, err)
		}
		if ks.Consumed() != 1 {
			t.Fatalf("initiate must draw exactly EK, drew %d", ks.Consumed())
		}
		ekPub, _ := X25519PublicKey(seedKey(0, 3))
		if !bytes.Equal(a.EKPub, ekPub) || a.SPKID != 7 || (withOPK != (a.OPKID != nil)) {
			t.Fatal("initiate result fields")
		}
		b, err := Respond(bob, PeerIdentity{Username: "alice", IKSig: alice.IKSigPub(), IKDH: alice.IKDHPub()},
			alice.IKBindSig(), a.EKPub, spkPriv, opkPriv)
		if err != nil {
			t.Fatalf("respond: %v", err)
		}
		if !bytes.Equal(a.SK, b.SK) || !bytes.Equal(a.WS, b.WS) || a.SID != b.SID || !bytes.Equal(a.AD, b.AD) {
			t.Fatalf("asymmetric (opk=%v)", withOPK)
		}
		if !bytes.Equal(a.DH1, b.DH1) || !bytes.Equal(a.DH2, b.DH2) || !bytes.Equal(a.DH3, b.DH3) || !bytes.Equal(a.DH4, b.DH4) {
			t.Fatal("DH outputs differ")
		}
		if withOPK != (a.DH4 != nil) {
			t.Fatal("DH4 presence")
		}
		// Derivations spelled out.
		ikm := Concat(bytes.Repeat([]byte{0xff}, 32), a.DH1, a.DH2, a.DH3, a.DH4)
		if !bytes.Equal(a.SK, HKDF(ikm, Zeros, []byte(InfoX3DH), 32)) {
			t.Fatal("SK derivation")
		}
		if !bytes.Equal(a.WS, HKDF(a.SK, Zeros, []byte(InfoWMSecret), 32)) {
			t.Fatal("WS derivation")
		}
		if a.SID != SID(ekPub) || !bytes.Equal(a.SID[:], SHA256([]byte("Kilit_SID_v1"), ekPub)[:8]) {
			t.Fatal("SID derivation")
		}
		wantAD := Concat(alice.IKSigPub(), alice.IKDHPub(), bob.IKSigPub(), bob.IKDHPub(),
			[]byte{0, 5}, []byte("alice"), []byte{0, 3}, []byte("bob"))
		if !bytes.Equal(a.AD, wantAD) {
			t.Fatal("AD layout")
		}
	}
	// SK differs with and without OPK; AD does not.
	bundleOPK, _, _ := setABobBundle(t, true)
	bundleNo, _, _ := setABobBundle(t, false)
	r1, _ := Initiate(setAAlice(), bundleOPK, nil, setATS, NewScriptedKeySource([][]byte{seedKey(0, 3)}))
	r2, _ := Initiate(setAAlice(), bundleNo, nil, setATS, NewScriptedKeySource([][]byte{seedKey(0, 3)}))
	if bytes.Equal(r1.SK, r2.SK) || !bytes.Equal(r1.AD, r2.AD) || r1.SID != r2.SID {
		t.Fatal("no_opk variant")
	}
}

func TestX3DHNegatives(t *testing.T) {
	alice := setAAlice()
	ks := func() KeySource { return NewScriptedKeySource([][]byte{seedKey(0, 3)}) }

	// identityMismatch: bundle ik_dh swapped for another key.
	bundle, _, _ := setABobBundle(t, true)
	other := Identity{Username: "bob", IKSigSeed: setABob().IKSigSeed, IKDHPriv: seedKey(0x10, 9)}
	bundle.IKDH = other.IKDHPub()
	bundle.IKBindSig = other.IKBindSig()
	known := PeerIdentity{Username: "bob", IKSig: setABob().IKSigPub(), IKDH: setABob().IKDHPub()}
	if _, err := Initiate(alice, bundle, &known, setATS, ks()); !errors.Is(err, ErrIdentityMismatch) {
		t.Errorf("ik_dh swapped: %v", err)
	}
	if err := CheckIdentity(known, PeerIdentity{Username: "bob", IKSig: known.IKSig, IKDH: bundle.IKDH}); !errors.Is(err, ErrIdentityMismatch) {
		t.Error("CheckIdentity")
	}
	if err := CheckIdentity(known, known); err != nil {
		t.Error("CheckIdentity equal")
	}

	// badSignature: ik_bind_sig over the wrong key.
	bundle, _, _ = setABobBundle(t, true)
	bundle.IKBindSig = Sign(setABob().IKSigSeed, IKBindMessage(other.IKDHPub()))
	if _, err := Initiate(alice, bundle, nil, setATS, ks()); !errors.Is(err, ErrBadSignature) {
		t.Errorf("bad bind sig: %v", err)
	}
	bundle, _, _ = setABobBundle(t, true)
	bundle.SPKSig[0] ^= 1
	if _, err := Initiate(alice, bundle, nil, setATS, ks()); !errors.Is(err, ErrBadSignature) {
		t.Errorf("bad spk sig: %v", err)
	}

	// staleSPK: created_at = ts − 22 d; 21 d exactly is still fresh.
	bundle, _, _ = setABobBundle(t, true)
	stale := uint64(setATS - 22*86400)
	bundle.SPKCreatedAt = stale
	bundle.SPKSig = Sign(setABob().IKSigSeed, SPKMessage(7, stale, bundle.SPKPub))
	if _, err := Initiate(alice, bundle, nil, setATS, ks()); !errors.Is(err, ErrStaleSPK) {
		t.Errorf("stale spk: %v", err)
	}
	edge := uint64(setATS - 21*86400)
	bundle.SPKCreatedAt = edge
	bundle.SPKSig = Sign(setABob().IKSigSeed, SPKMessage(7, edge, bundle.SPKPub))
	if _, err := Initiate(alice, bundle, nil, setATS, ks()); err != nil {
		t.Errorf("21 d exactly: %v", err)
	}

	// badKeyLength on short keys, badPublicKey on a small-order IK_sig.
	bundle, _, _ = setABobBundle(t, true)
	bundle.SPKPub = bundle.SPKPub[:31]
	if _, err := Initiate(alice, bundle, nil, setATS, ks()); !errors.Is(err, ErrBadKeyLength) {
		t.Errorf("short spk: %v", err)
	}
	bundle, _, _ = setABobBundle(t, true)
	bundle.IKSig = SmallOrderPoints[2]
	if _, err := Initiate(alice, bundle, nil, setATS, ks()); !errors.Is(err, ErrBadPublicKey) {
		t.Errorf("small-order ik_sig: %v", err)
	}
	bundle, _, _ = setABobBundle(t, true)
	bundle.OPKPub = make([]byte, 32) // low-order OPK → lowOrderPoint
	if _, err := Initiate(alice, bundle, nil, setATS, ks()); !errors.Is(err, ErrLowOrderPoint) {
		t.Errorf("low-order opk: %v", err)
	}

	// Responder side.
	bundle, spkPriv, opkPriv := setABobBundle(t, true)
	a, _ := Initiate(alice, bundle, nil, setATS, ks())
	peer := PeerIdentity{Username: "alice", IKSig: alice.IKSigPub(), IKDH: alice.IKDHPub()}
	if _, err := Respond(setABob(), peer, alice.IKBindSig(), a.EKPub[:31], spkPriv, opkPriv); !errors.Is(err, ErrBadKeyLength) {
		t.Errorf("respond short ek: %v", err)
	}
	wrongSig := Sign(alice.IKSigSeed, IKBindMessage(other.IKDHPub()))
	if _, err := Respond(setABob(), peer, wrongSig, a.EKPub, spkPriv, opkPriv); !errors.Is(err, ErrBadSignature) {
		t.Errorf("respond bad bind: %v", err)
	}
	if _, err := Respond(setABob(), peer, alice.IKBindSig(), make([]byte, 32), spkPriv, opkPriv); !errors.Is(err, ErrLowOrderPoint) {
		t.Errorf("respond low-order ek: %v", err)
	}
}
