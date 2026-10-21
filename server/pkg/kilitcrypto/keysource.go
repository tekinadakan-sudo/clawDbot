package kilitcrypto

import (
	"crypto/ecdh"
	"crypto/rand"
	"sync"
)

// X25519PublicKey returns the public key of a 32-byte private scalar.
func X25519PublicKey(priv []byte) ([]byte, error) {
	k, err := ecdh.X25519().NewPrivateKey(priv)
	if err != nil {
		return nil, ErrBadKeyLength
	}
	return k.PublicKey().Bytes(), nil
}

// X25519 is the Diffie-Hellman function of §3. Both inputs must be exactly
// 32 bytes (ErrBadKeyLength); an all-zero output (a low-order peer point) is
// ErrLowOrderPoint, matching crypto/ecdh's own rejection.
func X25519(priv, peerPub []byte) ([]byte, error) {
	if len(priv) != 32 || len(peerPub) != 32 {
		return nil, ErrBadKeyLength
	}
	k, err := ecdh.X25519().NewPrivateKey(priv)
	if err != nil {
		return nil, ErrBadKeyLength
	}
	p, err := ecdh.X25519().NewPublicKey(peerPub)
	if err != nil {
		return nil, ErrBadKeyLength
	}
	out, err := k.ECDH(p)
	if err != nil {
		return nil, ErrLowOrderPoint
	}
	// Belt and braces: crypto/ecdh already rejects an all-zero output, but the
	// rule is a protocol invariant, so check it here as the Swift side does.
	var acc byte
	for _, b := range out {
		acc |= b
	}
	if acc == 0 {
		return nil, ErrLowOrderPoint
	}
	return out, nil
}

// KeySource is GENERATE_DH (§3.3): it yields fresh 32-byte X25519 private
// scalars. X3DH.initiate draws EK first, RatchetInitAlice the first DHs, and
// every DHRatchet one key; nothing else consumes it (§3.8).
type KeySource interface {
	X25519Private() ([]byte, error)
}

// FileKeySource yields fresh 32-byte attachment file keys (§3.5). It is a
// separate interface so that attachment seals can never shift the scripted
// EK/DHs consumption order of a ratchet scenario.
type FileKeySource interface {
	FileKey() ([]byte, error)
}

// RandomKeySource draws from crypto/rand; it is the production source.
type RandomKeySource struct{}

func (RandomKeySource) X25519Private() ([]byte, error) { return random32() }
func (RandomKeySource) FileKey() ([]byte, error)       { return random32() }

func random32() ([]byte, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// ScriptedKeySource hands out a fixed list of 32-byte values in order (the
// key_sources lists of the vector files). It serves both KeySource and
// FileKeySource from the same list; a scenario never mixes the two.
type ScriptedKeySource struct {
	mu   sync.Mutex
	keys [][]byte
	next int
}

// NewScriptedKeySource copies keys; each must be 32 bytes.
func NewScriptedKeySource(keys [][]byte) *ScriptedKeySource {
	s := &ScriptedKeySource{}
	for _, k := range keys {
		if len(k) != 32 {
			panic("kilitcrypto: scripted key must be 32 bytes")
		}
		s.keys = append(s.keys, append([]byte(nil), k...))
	}
	return s
}

func (s *ScriptedKeySource) draw() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.next >= len(s.keys) {
		return nil, ErrKeySourceExhausted
	}
	k := append([]byte(nil), s.keys[s.next]...)
	s.next++
	return k, nil
}

func (s *ScriptedKeySource) X25519Private() ([]byte, error) { return s.draw() }
func (s *ScriptedKeySource) FileKey() ([]byte, error)       { return s.draw() }

// Consumed reports how many keys have been drawn so far.
func (s *ScriptedKeySource) Consumed() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.next
}
