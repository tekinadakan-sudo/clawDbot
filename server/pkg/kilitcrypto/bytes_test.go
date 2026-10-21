package kilitcrypto

import (
	"bytes"
	"errors"
	"testing"
)

func TestBase64urlRoundTrip(t *testing.T) {
	cases := []struct {
		in   []byte
		text string
	}{
		{[]byte{}, ""},
		{[]byte{0x01}, "AQ"},
		{[]byte{0x01, 0x02}, "AQI"},
		{[]byte{0x01, 0x02, 0x03}, "AQID"},
		{[]byte{0xfb, 0xff, 0xbf}, "-_-_"},
		{[]byte{0xff, 0xfe, 0x80, 0x7f}, "__6Afw"},
	}
	for _, c := range cases {
		if got := Base64url(c.in); got != c.text {
			t.Errorf("Base64url(%x) = %q, want %q", c.in, got, c.text)
		}
		back, err := Base64urlDecode(c.text)
		if err != nil || !bytes.Equal(back, c.in) {
			t.Errorf("decode %q = %x, %v", c.text, back, err)
		}
	}
}

func TestBase64urlStrictNegatives(t *testing.T) {
	for _, text := range []string{
		"AQ==",     // padding
		"AQ+/",     // alphabet (+ /)
		"AQ ID",    // whitespace
		"AQID\n",   // newline, which Go's decoder would skip
		"AQIDB",    // length ≡ 1 (mod 4)
		"AR",       // non-zero trailing bits
		"AQI=",     // padding again
		"A\x00QID", // NUL
	} {
		if _, err := Base64urlDecode(text); !errors.Is(err, ErrBadEnvelope) {
			t.Errorf("decode %q: err = %v, want bad_envelope", text, err)
		}
	}
}

func TestBigEndianHelpers(t *testing.T) {
	if !bytes.Equal(U16BE(0x1234), []byte{0x12, 0x34}) {
		t.Error("U16BE")
	}
	if !bytes.Equal(U32BE(0x01020304), []byte{1, 2, 3, 4}) {
		t.Error("U32BE")
	}
	if !bytes.Equal(U64BE(1760000000), Hex("0000000068e77800")) {
		t.Errorf("U64BE = %x", U64BE(1760000000))
	}
	if !bytes.Equal(Concat([]byte{1}, nil, []byte{2, 3}), []byte{1, 2, 3}) {
		t.Error("Concat")
	}
}

func TestCanonicalUsername(t *testing.T) {
	for in, want := range map[string]string{"Alice": "alice", "bob_1": "bob_1", "ABC": "abc"} {
		if got, err := CanonicalUsername(in); err != nil || got != want {
			t.Errorf("CanonicalUsername(%q) = %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{"ab", "a-b", "ayşe", "", "abcdefghijklmnopqrstuvwxyz0123456789"} {
		if _, err := CanonicalUsername(bad); err == nil {
			t.Errorf("CanonicalUsername(%q) accepted", bad)
		}
	}
	if !ValidDeviceID("6f1d2c3b-4a59-4e8f-9b0c-1d2e3f4a5b6c") {
		t.Error("valid device id rejected")
	}
	for _, bad := range []string{"6F1D2C3B-4A59-4E8F-9B0C-1D2E3F4A5B6C", "6f1d2c3b-4a59-1e8f-9b0c-1d2e3f4a5b6c", "6f1d2c3b-4a59-4e8f-7b0c-1d2e3f4a5b6c"} {
		if ValidDeviceID(bad) {
			t.Errorf("ValidDeviceID(%q) accepted", bad)
		}
	}
}
