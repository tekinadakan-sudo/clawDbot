package kilitcrypto

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"regexp"
	"strings"
)

// Hex decodes lowercase or uppercase hex; it panics on malformed input and is
// meant for constants and vectors, never for wire data.
func Hex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("kilitcrypto: bad hex constant: " + err.Error())
	}
	return b
}

// HexString encodes b as lowercase hex (the vector-file encoding, §3.9).
func HexString(b []byte) string { return hex.EncodeToString(b) }

// Base64url encodes b with the unpadded URL alphabet (RFC 4648 §5).
func Base64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// Base64urlDecode is the strict decoder of §3: it rejects padding, any
// character outside A-Za-z0-9-_ (Go's decoder would silently skip \r and \n,
// so the alphabet is checked by hand first), an encoded length ≡ 1 (mod 4) and
// non-zero trailing bits in the last character. Failures are ErrBadEnvelope.
func Base64urlDecode(s string) ([]byte, error) {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return nil, ErrBadEnvelope
		}
	}
	if len(s)%4 == 1 {
		return nil, ErrBadEnvelope
	}
	out, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil, ErrBadEnvelope
	}
	return out, nil
}

// U16BE, U32BE and U64BE are the big-endian integer encodings of §3.
func U16BE(v uint16) []byte { return binary.BigEndian.AppendUint16(nil, v) }
func U32BE(v uint32) []byte { return binary.BigEndian.AppendUint32(nil, v) }
func U64BE(v uint64) []byte { return binary.BigEndian.AppendUint64(nil, v) }

// Concat joins byte strings (the || operator of the design).
func Concat(parts ...[]byte) []byte {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	out := make([]byte, 0, n)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

var (
	usernameRe = regexp.MustCompile(`^[a-z0-9_]{3,32}$`)
	deviceIDRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
)

// CanonicalUsername lowercases ASCII letters and validates ^[a-z0-9_]{3,32}$
// (§3). Every signature, AD and hash in this package is computed over the
// canonical form.
func CanonicalUsername(s string) (string, error) {
	c := strings.ToLower(s)
	if !usernameRe.MatchString(c) {
		return "", ErrBadEnvelope
	}
	return c, nil
}

// ValidDeviceID reports whether s is a lowercase UUIDv4 string (§3).
func ValidDeviceID(s string) bool { return deviceIDRe.MatchString(s) }
