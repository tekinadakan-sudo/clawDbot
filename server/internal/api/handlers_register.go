package api

import (
	"errors"
	"net/http"

	"github.com/tekinadakan-sudo/clawDbot/server/internal/auth"
	"github.com/tekinadakan-sudo/clawDbot/server/internal/store"
)

type spkJSON struct {
	CreatedAt int64  `json:"created_at"`
	ID        uint32 `json:"id"`
	Pub       string `json:"pub"`
	Sig       string `json:"sig"`
}

type opkJSON struct {
	ID  uint32 `json:"id"`
	Pub string `json:"pub"`
}

// parseSPK decodes and verifies spk.sig with signPub. ok=false means the error was written.
func (s *server) parseSPK(w http.ResponseWriter, in spkJSON, signPub []byte) (store.SignedPrekey, bool) {
	pub, err := b64(in.Pub)
	if err != nil {
		writeError(w, http.StatusBadRequest, codeBadJSON, "spk.pub must be base64url")
		return store.SignedPrekey{}, false
	}
	if len(pub) != 32 {
		writeError(w, http.StatusBadRequest, codeBadKeyLength, "spk.pub must be 32 bytes")
		return store.SignedPrekey{}, false
	}
	sig, err := b64(in.Sig)
	if err != nil {
		writeError(w, http.StatusBadRequest, codeBadJSON, "spk.sig must be base64url")
		return store.SignedPrekey{}, false
	}
	if in.CreatedAt <= 0 {
		writeError(w, http.StatusBadRequest, codeBadTS, "spk.created_at must be unix seconds")
		return store.SignedPrekey{}, false
	}
	if err := auth.Verify(signPub, auth.SPKMessage(in.ID, uint64(in.CreatedAt), pub), sig); err != nil {
		writeError(w, http.StatusBadRequest, codeBadSignature, "spk.sig does not verify")
		return store.SignedPrekey{}, false
	}
	return store.SignedPrekey{KeyID: in.ID, Pub: pub, Sig: sig, CreatedAt: in.CreatedAt}, true
}

// parseOPKs decodes the batch and, when non-empty, verifies opks_sig with signPub.
func (s *server) parseOPKs(w http.ResponseWriter, in []opkJSON, opksSig string, signPub []byte) ([]store.OneTimePrekey, bool) {
	if len(in) > store.MaxOPKs {
		writeError(w, http.StatusBadRequest, codeTooManyOPKs, "at most 500 one-time prekeys")
		return nil, false
	}
	out := make([]store.OneTimePrekey, 0, len(in))
	batch := make([]auth.OPK, 0, len(in))
	for _, o := range in {
		pub, err := b64(o.Pub)
		if err != nil {
			writeError(w, http.StatusBadRequest, codeBadJSON, "opks[].pub must be base64url")
			return nil, false
		}
		if len(pub) != 32 {
			writeError(w, http.StatusBadRequest, codeBadKeyLength, "opks[].pub must be 32 bytes")
			return nil, false
		}
		out = append(out, store.OneTimePrekey{KeyID: o.ID, Pub: pub})
		batch = append(batch, auth.OPK{ID: o.ID, Pub: pub})
	}
	if len(out) == 0 {
		return out, true
	}
	sig, err := b64(opksSig)
	if err != nil {
		writeError(w, http.StatusBadRequest, codeBadJSON, "opks_sig must be base64url")
		return nil, false
	}
	if err := auth.Verify(signPub, auth.OPKBatchMessage(batch), sig); err != nil {
		writeError(w, http.StatusBadRequest, codeBadSignature, "opks_sig does not verify")
		return nil, false
	}
	return out, true
}

// POST /v1/register. Order (§4.3.2/§4.5/§4.6): validate → clock skew → 409 username_taken before
// the register limiter → limiter → consume nonce → verify every signature → CreateUser.
func (s *server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username      string    `json:"username"`
		IKSig         string    `json:"ik_sig"`
		IKDH          string    `json:"ik_dh"`
		IKBindSig     string    `json:"ik_bind_sig"`
		RegisterProof string    `json:"register_proof"`
		Nonce         string    `json:"nonce"`
		TS            int64     `json:"ts"`
		SPK           spkJSON   `json:"spk"`
		OPKs          []opkJSON `json:"opks"`
		OPKsSig       string    `json:"opks_sig"`
		DeviceID      string    `json:"device_id"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	username, err := auth.CanonicalUsername(req.Username)
	if err != nil {
		writeError(w, http.StatusBadRequest, codeBadUsername, "username must match ^[a-z0-9_]{3,32}$")
		return
	}
	if !auth.ValidDeviceID(req.DeviceID) {
		writeError(w, http.StatusBadRequest, codeBadDeviceID, "device_id must be a lowercase UUIDv4")
		return
	}
	ikSig, err := b64(req.IKSig)
	if err != nil {
		writeError(w, http.StatusBadRequest, codeBadJSON, "ik_sig must be base64url")
		return
	}
	ikDH, err := b64(req.IKDH)
	if err != nil {
		writeError(w, http.StatusBadRequest, codeBadJSON, "ik_dh must be base64url")
		return
	}
	if len(ikSig) != 32 || len(ikDH) != 32 {
		writeError(w, http.StatusBadRequest, codeBadKeyLength, "ik_sig and ik_dh must be 32 bytes")
		return
	}
	if err := auth.CheckPublicKey(ikSig); err != nil {
		writeError(w, http.StatusBadRequest, codeBadSignature, "ik_sig is a small-order point")
		return
	}
	bindSig, err := b64(req.IKBindSig)
	if err != nil {
		writeError(w, http.StatusBadRequest, codeBadJSON, "ik_bind_sig must be base64url")
		return
	}
	proof, err := b64(req.RegisterProof)
	if err != nil {
		writeError(w, http.StatusBadRequest, codeBadJSON, "register_proof must be base64url")
		return
	}
	nonce, err := b64(req.Nonce)
	if err != nil || len(nonce) != auth.NonceSize {
		writeError(w, http.StatusBadRequest, codeBadJSON, "nonce must be base64url of 32 bytes")
		return
	}
	if req.TS <= 0 {
		writeError(w, http.StatusBadRequest, codeBadTS, "ts must be unix seconds")
		return
	}
	spk, ok := s.parseSPK(w, req.SPK, ikSig)
	if !ok {
		return
	}
	opks, ok := s.parseOPKs(w, req.OPKs, req.OPKsSig, ikSig)
	if !ok {
		return
	}
	now := s.now().Unix()
	if err := auth.CheckSkew(now, req.TS); err != nil {
		writeClockSkew(w, now)
		return
	}
	ctx := r.Context()
	if _, err := s.st.GetUserByName(ctx, username); err == nil {
		writeError(w, http.StatusConflict, codeUsernameTaken, "username is taken")
		return
	} else if !errors.Is(err, store.ErrNotFound) {
		s.log.Error("get user", "err", err)
		writeInternal(w)
		return
	}
	if !s.lim.register.Allow(s.ipKey(r)) {
		writeRateLimited(w)
		return
	}
	if err := auth.ConsumeNonce(ctx, s.st, nonce, username, now); err != nil {
		if errors.Is(err, auth.ErrNonceInvalid) {
			writeError(w, http.StatusUnauthorized, codeNonceInvalid, "nonce expired, unknown or already used")
			return
		}
		s.log.Error("consume nonce", "err", err)
		writeInternal(w)
		return
	}
	if err := auth.Verify(ikSig, auth.RegisterMessage(username, ikDH, req.DeviceID, nonce, uint64(req.TS), s.origin), proof); err != nil {
		writeError(w, http.StatusBadRequest, codeBadSignature, "register_proof does not verify")
		return
	}
	if err := auth.Verify(ikSig, auth.IKBindMessage(ikDH), bindSig); err != nil {
		writeError(w, http.StatusBadRequest, codeBadSignature, "ik_bind_sig does not verify")
		return
	}
	token, hash, err := auth.NewToken()
	if err != nil {
		writeInternal(w)
		return
	}
	exp := now + auth.TokenTTL
	uid, err := s.st.CreateUser(ctx, store.NewUser{
		Username:        username,
		IdentitySignPub: ikSig,
		IdentityDHPub:   ikDH,
		IdentityBindSig: bindSig,
		SPK:             spk,
		OPKs:            opks,
		DeviceID:        req.DeviceID,
		TokenHash:       hash,
		TokenExpiresAt:  exp,
	})
	if err != nil {
		switch {
		case errors.Is(err, store.ErrUsernameTaken):
			writeError(w, http.StatusConflict, codeUsernameTaken, "username is taken")
		case errors.Is(err, store.ErrKeyInUse):
			writeError(w, http.StatusConflict, codeKeyInUse, "identity key already registered")
		case errors.Is(err, store.ErrOPKExists):
			writeError(w, http.StatusConflict, codeOPKExists, "duplicate one-time prekey id")
		case errors.Is(err, store.ErrTooManyOPKs):
			writeError(w, http.StatusBadRequest, codeTooManyOPKs, "at most 500 one-time prekeys")
		default:
			s.log.Error("create user", "err", err)
			writeInternal(w)
		}
		return
	}
	writeJSON(w, http.StatusCreated, struct {
		ExpiresAt int64  `json:"expires_at"`
		Token     string `json:"token"`
		UserID    int64  `json:"user_id"`
	}{exp, token, uid})
}
