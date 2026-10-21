package api

import (
	"encoding/json"
	"net/http"
)

// Error codes of §4.3.1.
const (
	codeBadJSON          = "bad_json"
	codeBadUsername      = "bad_username"
	codeBadDeviceID      = "bad_device_id"
	codeBadKeyLength     = "bad_key_length"
	codeBadSignature     = "bad_signature"
	codeSPKNotMonotonic  = "spk_not_monotonic"
	codeTooManyOPKs      = "too_many_opks"
	codeBadMsgID         = "bad_msg_id"
	codeBadBlobID        = "bad_blob_id"
	codeBadTS            = "bad_ts"
	codeInvalidToken     = "invalid_token"
	codeNonceInvalid     = "nonce_invalid"
	codeClockSkew        = "clock_skew"
	codeForbidden        = "forbidden"
	codeUnknownUser      = "unknown_user"
	codeNotFound         = "not_found"
	codeUsernameTaken    = "username_taken"
	codeKeyInUse         = "key_in_use"
	codeOPKExists        = "opk_exists"
	codeBlobExists       = "blob_exists"
	codeMsgIDConflict    = "msg_id_conflict"
	codeBodyTooLarge     = "body_too_large"
	codeEnvelopeTooLarge = "envelope_too_large"
	codeRateLimited      = "rate_limited"
	codeRecipientFull    = "recipient_full"
	codeInternal         = "internal"
)

// errorBody is the JSON error shape; server_time is only present on clock_skew.
type errorBody struct {
	Error      string `json:"error"`
	Message    string `json:"message"`
	ServerTime *int64 `json:"server_time,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, errorBody{Error: code, Message: msg})
}

func writeClockSkew(w http.ResponseWriter, serverTime int64) {
	writeJSON(w, http.StatusUnauthorized, errorBody{Error: codeClockSkew, Message: "ts is more than 300 s from server time", ServerTime: &serverTime})
}

func writeRateLimited(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "1")
	writeError(w, http.StatusTooManyRequests, codeRateLimited, "rate limited")
}

func writeInternal(w http.ResponseWriter) {
	writeError(w, http.StatusInternalServerError, codeInternal, "internal error")
}
