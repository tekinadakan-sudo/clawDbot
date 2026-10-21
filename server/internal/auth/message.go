// Package auth implements kilitd's signed-challenge authentication (design §3.1, §4.5): strict
// Ed25519 verification, the canonical signed-message layouts, nonces, tokens and the bearer
// middleware. It never imports pkg/kilitcrypto; the strictness rule is implemented here as well.
package auth

import (
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net/url"
	"regexp"
	"strings"
)

// Errors of the verification and validation helpers.
var (
	ErrBadKeyLength = errors.New("auth: bad key length")
	ErrBadSignature = errors.New("auth: bad signature")
	ErrBadUsername  = errors.New("auth: bad username")
	ErrBadDeviceID  = errors.New("auth: bad device id")
)

// Domain-separation prefixes of §3.1.
const (
	PrefixIKBind   = "Kilit_IKBind_v1"
	PrefixSPK      = "Kilit_SPK_v1"
	PrefixOPKBatch = "Kilit_OPKBatch_v1"
	PrefixRegister = "Kilit_Register_v1"
	PrefixAuth     = "Kilit_Auth_v1"
	PrefixDelete   = "Kilit_Delete_v1"
)

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// ed25519L is the group order L as 32 little-endian bytes; S of a signature must be < L.
var ed25519L = mustHex("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010")

// smallOrderPoints are the 14 encodings of §3 (libsodium's 7-entry blacklist with both sign bits)
// that neither a public key A nor a signature's R may equal.
var smallOrderPoints = [14][]byte{
	mustHex("0000000000000000000000000000000000000000000000000000000000000000"),
	mustHex("0000000000000000000000000000000000000000000000000000000000000080"),
	mustHex("0100000000000000000000000000000000000000000000000000000000000000"),
	mustHex("0100000000000000000000000000000000000000000000000000000000000080"),
	mustHex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"),
	mustHex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85"),
	mustHex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"),
	mustHex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"),
	mustHex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
	mustHex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
	mustHex("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
	mustHex("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
	mustHex("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
	mustHex("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
}

// IsSmallOrder reports whether the 32-byte encoding p is in the small-order table.
func IsSmallOrder(p []byte) bool {
	hit := 0
	for _, q := range smallOrderPoints {
		hit |= subtle.ConstantTimeCompare(p, q)
	}
	return hit == 1
}

// scalarLessThanL compares S against L from index 31 downwards; equal → false (§3).
func scalarLessThanL(s []byte) bool {
	for i := 31; i >= 0; i-- {
		if s[i] != ed25519L[i] {
			return s[i] < ed25519L[i]
		}
	}
	return false
}

// CheckPublicKey is the import-time check: exactly 32 bytes and not small-order.
func CheckPublicKey(pub []byte) error {
	if len(pub) != ed25519.PublicKeySize {
		return ErrBadKeyLength
	}
	if IsSmallOrder(pub) {
		return ErrBadSignature
	}
	return nil
}

// Verify runs the strict pre-checks of §3 (signature length 64, S < L, neither A nor R
// small-order) before crypto/ed25519's verify. A wrong public key length is ErrBadKeyLength,
// every other failure ErrBadSignature.
func Verify(pub, msg, sig []byte) error {
	if len(pub) != ed25519.PublicKeySize {
		return ErrBadKeyLength
	}
	if len(sig) != ed25519.SignatureSize {
		return ErrBadSignature
	}
	if !scalarLessThanL(sig[32:64]) {
		return ErrBadSignature
	}
	if IsSmallOrder(pub) || IsSmallOrder(sig[:32]) {
		return ErrBadSignature
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), msg, sig) {
		return ErrBadSignature
	}
	return nil
}

// OPK is one one-time prekey of an opks_sig batch.
type OPK struct {
	ID  uint32
	Pub []byte
}

func u32(v uint32) []byte { return binary.BigEndian.AppendUint32(nil, v) }
func u64(v uint64) []byte { return binary.BigEndian.AppendUint64(nil, v) }

func concat(parts ...[]byte) []byte {
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

var sep = []byte{0x00}

// IKBindMessage = "Kilit_IKBind_v1" || IK_dh_pub.
func IKBindMessage(ikDHPub []byte) []byte {
	return concat([]byte(PrefixIKBind), ikDHPub)
}

// SPKMessage = "Kilit_SPK_v1" || u32BE(spk_id) || u64BE(created_at) || SPK_pub.
func SPKMessage(spkID uint32, createdAt uint64, spkPub []byte) []byte {
	return concat([]byte(PrefixSPK), u32(spkID), u64(createdAt), spkPub)
}

// OPKBatchMessage = "Kilit_OPKBatch_v1" || u32BE(count) || (u32BE(id) || pub)… in request order.
func OPKBatchMessage(opks []OPK) []byte {
	out := concat([]byte(PrefixOPKBatch), u32(uint32(len(opks))))
	for _, o := range opks {
		out = append(out, u32(o.ID)...)
		out = append(out, o.Pub...)
	}
	return out
}

// RegisterMessage = "Kilit_Register_v1" || 0x00 || username || 0x00 || IK_dh_pub || 0x00 ||
// device_id || 0x00 || nonce || 0x00 || u64BE(ts) || 0x00 || server_origin.
func RegisterMessage(username string, ikDHPub []byte, deviceID string, nonce []byte, ts uint64, serverOrigin string) []byte {
	return concat([]byte(PrefixRegister), sep, []byte(username), sep, ikDHPub, sep,
		[]byte(deviceID), sep, nonce, sep, u64(ts), sep, []byte(serverOrigin))
}

// LoginMessage = "Kilit_Auth_v1" || 0x00 || username || 0x00 || nonce || 0x00 || u64BE(ts) ||
// 0x00 || device_id || 0x00 || server_origin.
func LoginMessage(username string, nonce []byte, ts uint64, deviceID, serverOrigin string) []byte {
	return concat([]byte(PrefixAuth), sep, []byte(username), sep, nonce, sep, u64(ts), sep,
		[]byte(deviceID), sep, []byte(serverOrigin))
}

// DeleteMessage = "Kilit_Delete_v1" || 0x00 || username || 0x00 || nonce || 0x00 || u64BE(ts) ||
// 0x00 || server_origin.
func DeleteMessage(username string, nonce []byte, ts uint64, serverOrigin string) []byte {
	return concat([]byte(PrefixDelete), sep, []byte(username), sep, nonce, sep, u64(ts), sep,
		[]byte(serverOrigin))
}

var (
	usernameRe = regexp.MustCompile(`^[a-z0-9_]{3,32}$`)
	deviceIDRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
)

// CanonicalUsername lowercases ASCII letters and checks ^[a-z0-9_]{3,32}$ (§3).
func CanonicalUsername(s string) (string, error) {
	if len(s) > 32 {
		return "", ErrBadUsername
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b.WriteByte(c)
	}
	u := b.String()
	if !usernameRe.MatchString(u) {
		return "", ErrBadUsername
	}
	return u, nil
}

// ValidDeviceID reports whether s is a lowercase UUIDv4 string.
func ValidDeviceID(s string) bool { return deviceIDRe.MatchString(s) }

// CanonicalOrigin rebuilds the server_origin of §3 from -public-origin: lowercase
// scheme://host[:port], no path, no trailing slash, default ports omitted.
func CanonicalOrigin(publicOrigin string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(publicOrigin))
	if err != nil {
		return "", err
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", errors.New("auth: origin scheme must be http or https")
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return "", errors.New("auth: origin host is empty")
	}
	if strings.Contains(host, ":") { // IPv6 literal
		host = "[" + host + "]"
	}
	port := u.Port()
	if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		port = ""
	}
	if port != "" {
		host += ":" + port
	}
	return scheme + "://" + host, nil
}
