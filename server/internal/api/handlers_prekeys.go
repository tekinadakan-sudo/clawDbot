package api

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/tekinadakan-sudo/clawDbot/server/internal/auth"
	"github.com/tekinadakan-sudo/clawDbot/server/internal/authctx"
	"github.com/tekinadakan-sudo/clawDbot/server/internal/store"
)

// prekeysLowThreshold is the OPK count below which the target is told to refill.
const prekeysLowThreshold = 20

type bundleJSON struct {
	IKBindSig string   `json:"ik_bind_sig"`
	IKDH      string   `json:"ik_dh"`
	IKSig     string   `json:"ik_sig"`
	OPK       *opkJSON `json:"opk"`
	SPK       spkJSON  `json:"spk"`
	Username  string   `json:"username"`
}

// GET /v1/users/{username}/prekeys: newest SPK, plus one claimed OPK unless a §4.6 quota is
// exceeded (then opk is null and the fetcher cannot tell).
func (s *server) handleGetPrekeys(w http.ResponseWriter, r *http.Request) {
	target, ok := s.lookupUser(w, r)
	if !ok {
		return
	}
	p, _ := authctx.PrincipalFrom(r.Context())
	claim := false
	if s.lim.claimPair.Allow(p.UserID, target.ID) {
		if s.lim.claimTarget.Allow(strconv.FormatInt(target.ID, 10)) {
			claim = true
		} else {
			// The per-target claim rate is tripped: log it and push prekeys_low so the target refills.
			s.log.Warn("opk claim quota exceeded for target", "target", target.ID)
			s.notifyPrekeys(r, target.ID, true)
		}
	}
	b, err := s.st.FetchBundle(r.Context(), target.ID, claim)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, codeUnknownUser, "unknown user")
			return
		}
		s.log.Error("fetch bundle", "err", err)
		writeInternal(w)
		return
	}
	out := bundleJSON{
		IKBindSig: b64s(b.IdentityBindSig),
		IKDH:      b64s(b.IdentityDHPub),
		IKSig:     b64s(b.IdentitySignPub),
		SPK:       spkJSON{CreatedAt: b.SPK.CreatedAt, ID: b.SPK.KeyID, Pub: b64s(b.SPK.Pub), Sig: b64s(b.SPK.Sig)},
		Username:  b.Username,
	}
	if b.OPK != nil {
		out.OPK = &opkJSON{ID: b.OPK.KeyID, Pub: b64s(b.OPK.Pub)}
	}
	writeJSON(w, http.StatusOK, out)
	if claim && b.OPK != nil {
		s.notifyPrekeys(r, target.ID, false)
	}
}

// notifyPrekeys calls Notifier.PrekeysLow for userID when its OPK count is below the threshold
// (or unconditionally when force is set, i.e. a quota tripped).
func (s *server) notifyPrekeys(r *http.Request, userID int64, force bool) {
	if s.n == nil {
		return
	}
	count, _, consumed, err := s.st.PrekeyCount(r.Context(), userID)
	if err != nil {
		return
	}
	if force || count < prekeysLowThreshold {
		s.n.PrekeysLow(userID, count, consumed)
	}
}

// PUT /v1/prekeys: {spk|null, opks, opks_sig} → {opk_count, spk_id}.
func (s *server) handlePutPrekeys(w http.ResponseWriter, r *http.Request) {
	si, _ := auth.SessionFrom(r.Context())
	var req struct {
		SPK     *spkJSON  `json:"spk"`
		OPKs    []opkJSON `json:"opks"`
		OPKsSig string    `json:"opks_sig"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	signPub := si.Session.IdentitySignPub
	var spk store.SignedPrekey
	if req.SPK != nil {
		var ok bool
		if spk, ok = s.parseSPK(w, *req.SPK, signPub); !ok {
			return
		}
	}
	opks, ok := s.parseOPKs(w, req.OPKs, req.OPKsSig, signPub)
	if !ok {
		return
	}
	ctx := r.Context()
	uid := si.Session.UserID
	if req.SPK != nil {
		if err := s.st.PutSignedPrekey(ctx, uid, spk); err != nil {
			if errors.Is(err, store.ErrSPKNotMonotonic) {
				writeError(w, http.StatusBadRequest, codeSPKNotMonotonic, "spk.id must exceed the current id")
				return
			}
			s.log.Error("put spk", "err", err)
			writeInternal(w)
			return
		}
	}
	if len(opks) > 0 {
		if _, err := s.st.PutOneTimePrekeys(ctx, uid, opks); err != nil {
			switch {
			case errors.Is(err, store.ErrOPKExists):
				writeError(w, http.StatusConflict, codeOPKExists, "one-time prekey id already stored or consumed")
			case errors.Is(err, store.ErrTooManyOPKs):
				writeError(w, http.StatusBadRequest, codeTooManyOPKs, "more than 500 one-time prekeys would be stored")
			default:
				s.log.Error("put opks", "err", err)
				writeInternal(w)
			}
			return
		}
	}
	count, spkID, _, err := s.st.PrekeyCount(ctx, uid)
	if err != nil {
		s.log.Error("prekey count", "err", err)
		writeInternal(w)
		return
	}
	writeJSON(w, http.StatusOK, struct {
		OPKCount int    `json:"opk_count"`
		SPKID    uint32 `json:"spk_id"`
	}{count, spkID})
}

// GET /v1/prekeys/count → {opk_count, spk_id, consumed_ids}.
func (s *server) handlePrekeyCount(w http.ResponseWriter, r *http.Request) {
	p, _ := authctx.PrincipalFrom(r.Context())
	count, spkID, consumed, err := s.st.PrekeyCount(r.Context(), p.UserID)
	if err != nil {
		s.log.Error("prekey count", "err", err)
		writeInternal(w)
		return
	}
	if consumed == nil {
		consumed = []uint32{}
	}
	writeJSON(w, http.StatusOK, struct {
		ConsumedIDs []uint32 `json:"consumed_ids"`
		OPKCount    int      `json:"opk_count"`
		SPKID       uint32   `json:"spk_id"`
	}{consumed, count, spkID})
}
