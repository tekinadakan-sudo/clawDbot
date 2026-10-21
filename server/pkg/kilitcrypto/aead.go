package kilitcrypto

import "golang.org/x/crypto/chacha20poly1305"

// Seal is ChaCha20-Poly1305 (RFC 8439) with an explicit 12-byte nonce; the
// wire form is ciphertext || tag(16), the nonce is never transmitted (it is
// derived with the key, §3.3 and §3.5).
func Seal(key, nonce, aad, pt []byte) ([]byte, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, ErrIncorrectKeySize
	}
	if len(nonce) != chacha20poly1305.NonceSize {
		return nil, ErrIncorrectParameterSize
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, ErrIncorrectKeySize
	}
	return aead.Seal(nil, nonce, pt, aad), nil
}

// Open reverses Seal. Any failure of the tag check is ErrAuthenticationFailure
// (CryptoKit's case name), including a wire shorter than the 16-byte tag.
func Open(key, nonce, aad, wire []byte) ([]byte, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, ErrIncorrectKeySize
	}
	if len(nonce) != chacha20poly1305.NonceSize {
		return nil, ErrIncorrectParameterSize
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, ErrIncorrectKeySize
	}
	pt, err := aead.Open(nil, nonce, wire, aad)
	if err != nil {
		return nil, ErrAuthenticationFailure
	}
	return pt, nil
}
