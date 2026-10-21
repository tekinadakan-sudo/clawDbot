package kilitcrypto

import (
	"crypto/sha256"
	"fmt"
	"strings"
)

// SafetyIterations is the number of extra hash rounds of §3.6.
const SafetyIterations = 5199

// SafetyDigits is one party's 30-digit half: h = SHA256("Kilit_SafetyNumber_v1"
// || IK_sig || IK_dh || username), then 5199 times h = SHA256(h || IK_sig ||
// IK_dh); h[0:30] as six 5-byte big-endian integers mod 100000, zero-padded.
func SafetyDigits(username string, ikSig, ikDH []byte) string {
	h := sha256.Sum256(Concat([]byte(PrefixSafety), ikSig, ikDH, []byte(username)))
	for i := 0; i < SafetyIterations; i++ {
		h = sha256.Sum256(Concat(h[:], ikSig, ikDH))
	}
	var sb strings.Builder
	for i := 0; i < 6; i++ {
		chunk := h[i*5 : i*5+5]
		var v uint64
		for _, b := range chunk {
			v = v<<8 | uint64(b)
		}
		fmt.Fprintf(&sb, "%05d", v%100000)
	}
	return sb.String()
}

// SafetyNumber is the 60-digit number of two parties: the lexicographically
// smaller 30-digit half first. The order of the arguments is irrelevant.
func SafetyNumber(a, b PeerIdentity) string {
	da := SafetyDigits(a.Username, a.IKSig, a.IKDH)
	db := SafetyDigits(b.Username, b.IKSig, b.IKDH)
	if db < da {
		da, db = db, da
	}
	return da + db
}

// SafetyQR is the QR payload kilit-sn:v1:<60 digits>.
func SafetyQR(number string) string { return "kilit-sn:v1:" + number }

// SafetyGroups renders the number in 12 groups of 5 digits separated by spaces.
func SafetyGroups(number string) string {
	parts := make([]string, 0, 12)
	for i := 0; i+5 <= len(number); i += 5 {
		parts = append(parts, number[i:i+5])
	}
	return strings.Join(parts, " ")
}
