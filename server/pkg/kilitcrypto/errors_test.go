package kilitcrypto

import (
	"errors"
	"fmt"
	"testing"
)

func TestErrorNames(t *testing.T) {
	cases := map[error]string{
		ErrLowOrderPoint: "lowOrderPoint", ErrBadKeyLength: "badKeyLength", ErrBadPublicKey: "badPublicKey",
		ErrBadSignature: "badSignature", ErrIdentityMismatch: "identityMismatch", ErrReplay: "replay",
		ErrStaleSPK: "staleSPK", ErrTooManySkipped: "tooManySkipped", ErrBadHeader: "badHeader",
		ErrBadPadding: "badPadding", ErrSizeLimit: "sizeLimit", ErrUnknownSession: "unknownSession",
		ErrAuthenticationFailure: "authenticationFailure", ErrIncorrectKeySize: "incorrectKeySize",
		ErrIncorrectParameterSize: "incorrectParameterSize", ErrBadEnvelope: "bad_envelope",
	}
	for err, name := range cases {
		if got := ErrorName(err); got != name {
			t.Errorf("ErrorName(%v) = %q, want %q", err, got, name)
		}
		if err.Error() != "kilitcrypto: "+name {
			t.Errorf("message %q does not carry the case name %q", err.Error(), name)
		}
		if got := ErrorName(fmt.Errorf("wrapped: %w", err)); got != name {
			t.Errorf("wrapped ErrorName = %q, want %q", got, name)
		}
	}
	if ErrorName(nil) != "" || ErrorName(errors.New("x")) != "" {
		t.Error("nil/unknown must map to empty")
	}
}
