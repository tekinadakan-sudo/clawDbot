// Package kilitcrypto is the Go reference implementation of the Kilit
// protocol (docs/DESIGN.md §3): X3DH session setup, the Double Ratchet with a
// ChaCha20-Poly1305 instantiation, envelope and attachment formats, the safety
// number and the forensic watermark payload. The Swift port in
// ios/Kilit/Sources/Crypto mirrors every function here byte for byte; the
// vectors under docs/vectors are generated from this package.
package kilitcrypto

import "errors"

// Sentinel errors. The message of each KilitCryptoError mirror is exactly the
// Swift case name after the package prefix, so vector files and logs on both
// platforms spell the same word (§3.9).
var (
	ErrLowOrderPoint    = errors.New("kilitcrypto: lowOrderPoint")
	ErrBadKeyLength     = errors.New("kilitcrypto: badKeyLength")
	ErrBadPublicKey     = errors.New("kilitcrypto: badPublicKey")
	ErrBadSignature     = errors.New("kilitcrypto: badSignature")
	ErrIdentityMismatch = errors.New("kilitcrypto: identityMismatch")
	ErrReplay           = errors.New("kilitcrypto: replay")
	ErrStaleSPK         = errors.New("kilitcrypto: staleSPK")
	ErrTooManySkipped   = errors.New("kilitcrypto: tooManySkipped")
	ErrBadHeader        = errors.New("kilitcrypto: badHeader")
	ErrBadPadding       = errors.New("kilitcrypto: badPadding")
	ErrSizeLimit        = errors.New("kilitcrypto: sizeLimit")
	ErrUnknownSession   = errors.New("kilitcrypto: unknownSession")

	// CryptoKit mirrors (§3.9 "CryptoKit cases").
	ErrAuthenticationFailure  = errors.New("kilitcrypto: authenticationFailure")
	ErrIncorrectKeySize       = errors.New("kilitcrypto: incorrectKeySize")
	ErrIncorrectParameterSize = errors.New("kilitcrypto: incorrectParameterSize")

	// ErrBadEnvelope is the §3.2b step 1 classification for an outer envelope
	// that fails to parse for a reason other than its header (which is
	// ErrBadHeader). Both are classified bad_envelope by the inbound pipeline.
	ErrBadEnvelope = errors.New("kilitcrypto: bad_envelope")

	// ErrKeySourceExhausted is returned by a ScriptedKeySource whose list has
	// run out; it never occurs in production.
	ErrKeySourceExhausted = errors.New("kilitcrypto: key source exhausted")

	// ErrNoSendingChain is returned when a responder state encrypts before it
	// has decrypted the initiator's first message (CKs is still nil).
	ErrNoSendingChain = errors.New("kilitcrypto: sending chain not initialised")
)

// ErrorName returns the Swift case name for err (the string vector files use),
// or "" for nil and an unknown error.
func ErrorName(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrLowOrderPoint):
		return "lowOrderPoint"
	case errors.Is(err, ErrBadKeyLength):
		return "badKeyLength"
	case errors.Is(err, ErrBadPublicKey):
		return "badPublicKey"
	case errors.Is(err, ErrBadSignature):
		return "badSignature"
	case errors.Is(err, ErrIdentityMismatch):
		return "identityMismatch"
	case errors.Is(err, ErrReplay):
		return "replay"
	case errors.Is(err, ErrStaleSPK):
		return "staleSPK"
	case errors.Is(err, ErrTooManySkipped):
		return "tooManySkipped"
	case errors.Is(err, ErrBadHeader):
		return "badHeader"
	case errors.Is(err, ErrBadPadding):
		return "badPadding"
	case errors.Is(err, ErrSizeLimit):
		return "sizeLimit"
	case errors.Is(err, ErrUnknownSession):
		return "unknownSession"
	case errors.Is(err, ErrAuthenticationFailure):
		return "authenticationFailure"
	case errors.Is(err, ErrIncorrectKeySize):
		return "incorrectKeySize"
	case errors.Is(err, ErrIncorrectParameterSize):
		return "incorrectParameterSize"
	case errors.Is(err, ErrBadEnvelope):
		return "bad_envelope"
	}
	return ""
}
