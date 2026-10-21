package api

import (
	"net/http"

	"github.com/tekinadakan-sudo/clawDbot/server/internal/auth"
)

// PUT /v1/devices/{device_id}/push-token: {token, env} → 204; {device_id} must be the session's.
func (s *server) handlePushToken(w http.ResponseWriter, r *http.Request) {
	si, _ := auth.SessionFrom(r.Context())
	deviceID := r.PathValue("device_id")
	if !auth.ValidDeviceID(deviceID) {
		writeError(w, http.StatusBadRequest, codeBadDeviceID, "device_id must be a lowercase UUIDv4")
		return
	}
	if deviceID != si.Session.DeviceID {
		writeError(w, http.StatusForbidden, codeForbidden, "device_id is not this session's device")
		return
	}
	var req struct {
		Token string `json:"token"`
		Env   string `json:"env"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if req.Token == "" || len(req.Token) > 512 || (req.Env != "sandbox" && req.Env != "production") {
		writeError(w, http.StatusBadRequest, codeBadJSON, "token must be non-empty and env sandbox|production")
		return
	}
	if err := s.st.PutPushToken(r.Context(), si.Session.UserID, deviceID, req.Token, req.Env); err != nil {
		s.log.Error("put push token", "err", err)
		writeInternal(w)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
