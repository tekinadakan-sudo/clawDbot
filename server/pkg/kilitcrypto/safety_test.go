package kilitcrypto

import (
	"crypto/sha256"
	"strings"
	"testing"
)

func TestSafetyNumber(t *testing.T) {
	alice, bob := setAAlice(), setABob()
	a := PeerIdentity{Username: "alice", IKSig: alice.IKSigPub(), IKDH: alice.IKDHPub()}
	b := PeerIdentity{Username: "bob", IKSig: bob.IKSigPub(), IKDH: bob.IKDHPub()}
	da := SafetyDigits(a.Username, a.IKSig, a.IKDH)
	if len(da) != 30 || strings.Trim(da, "0123456789") != "" {
		t.Fatalf("digits = %q", da)
	}
	if da != SafetyDigits(a.Username, a.IKSig, a.IKDH) {
		t.Fatal("not deterministic")
	}
	// Spelled-out derivation.
	h := sha256.Sum256(Concat([]byte("Kilit_SafetyNumber_v1"), a.IKSig, a.IKDH, []byte("alice")))
	for i := 0; i < 5199; i++ {
		h = sha256.Sum256(Concat(h[:], a.IKSig, a.IKDH))
	}
	var want strings.Builder
	for i := 0; i < 6; i++ {
		v := uint64(0)
		for _, c := range h[i*5 : i*5+5] {
			v = v<<8 | uint64(c)
		}
		want.WriteString(strings.Repeat("0", 5-len(itoa(v%100000))) + itoa(v%100000))
	}
	if da != want.String() {
		t.Fatalf("digits %s != %s", da, want.String())
	}
	db := SafetyDigits(b.Username, b.IKSig, b.IKDH)
	n1, n2 := SafetyNumber(a, b), SafetyNumber(b, a)
	if n1 != n2 || len(n1) != 60 {
		t.Fatal("order dependence")
	}
	lo, hi := da, db
	if hi < lo {
		lo, hi = hi, lo
	}
	if n1 != lo+hi {
		t.Fatal("smaller half must come first")
	}
	if SafetyQR(n1) != "kilit-sn:v1:"+n1 {
		t.Fatal("qr")
	}
	if g := SafetyGroups(n1); len(strings.Fields(g)) != 12 || strings.ReplaceAll(g, " ", "") != n1 {
		t.Fatalf("groups = %q", g)
	}
	// Different username → different digits even with equal keys.
	if SafetyDigits("alice2", a.IKSig, a.IKDH) == da {
		t.Fatal("username not bound")
	}
}

func itoa(v uint64) string {
	if v == 0 {
		return "0"
	}
	var b []byte
	for v > 0 {
		b = append([]byte{byte('0' + v%10)}, b...)
		v /= 10
	}
	return string(b)
}
