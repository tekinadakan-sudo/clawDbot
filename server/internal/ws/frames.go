package ws

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"

	"github.com/tekinadakan-sudo/clawDbot/server/internal/store"
)

// Wire frames of design §4.4 (text frames, JSON).

// clientFrame is every frame a client may send: hello (first frame), ack, ping.
type clientFrame struct {
	T      string   `json:"t"`
	After  *int64   `json:"after,omitempty"`
	MsgIDs []string `json:"msg_ids,omitempty"`
}

type msgFrame struct {
	T        string `json:"t"`
	ID       int64  `json:"id"`
	MsgID    string `json:"msg_id"`
	From     string `json:"from"`
	Envelope string `json:"envelope"`
	TS       int64  `json:"ts"`
}

type prekeysLowFrame struct {
	T           string   `json:"t"`
	OPKCount    int      `json:"opk_count"`
	ConsumedIDs []uint32 `json:"consumed_ids"`
}

type errorFrame struct {
	T    string `json:"t"`
	Code string `json:"code"`
}

const (
	codeBadFrame    = "bad_frame"
	codeRateLimited = "rate_limited"
)

var b64 = base64.RawURLEncoding.Strict()

func encodeMsg(d Delivery) []byte {
	b, _ := json.Marshal(msgFrame{T: "msg", ID: d.ID, MsgID: d.MsgID, From: d.From, Envelope: b64.EncodeToString(d.Envelope), TS: d.TS})
	return b
}

func encodePrekeysLow(count int, consumed []uint32) []byte {
	if consumed == nil {
		consumed = []uint32{}
	}
	b, _ := json.Marshal(prekeysLowFrame{T: "prekeys_low", OPKCount: count, ConsumedIDs: consumed})
	return b
}

func encodeError(code string) []byte {
	b, _ := json.Marshal(errorFrame{T: "error", Code: code})
	return b
}

var pongFrame = []byte(`{"t":"pong"}`)

// deliveryFromRow converts a drained store row to the wire representation (MsgID hex-encoded).
func deliveryFromRow(q store.QueuedMessage) Delivery {
	return Delivery{ID: q.ID, MsgID: hex.EncodeToString(q.MsgID), From: q.SenderUsername, Envelope: q.Envelope, TS: q.CreatedAt}
}

// parseMsgIDs decodes ack ids: each must be 32 lowercase hex chars (16 bytes), at most MaxAckIDs.
func parseMsgIDs(ids []string) ([][]byte, bool) {
	if len(ids) > store.MaxAckIDs {
		return nil, false
	}
	out := make([][]byte, 0, len(ids))
	for _, s := range ids {
		if len(s) != 32 {
			return nil, false
		}
		for i := 0; i < len(s); i++ {
			c := s[i]
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
				return nil, false
			}
		}
		b, err := hex.DecodeString(s)
		if err != nil {
			return nil, false
		}
		out = append(out, b)
	}
	return out, true
}
