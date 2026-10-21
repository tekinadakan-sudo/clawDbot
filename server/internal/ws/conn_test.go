package ws

import (
	"encoding/json"
	"testing"

	"github.com/tekinadakan-sudo/clawDbot/server/internal/store"
)

func TestMergeBuffered(t *testing.T) {
	in := []item{{id: 7}, {id: 0, payload: []byte("low")}, {id: 5}, {id: 9}, {id: 8}, {id: 7}}
	out := mergeBuffered(in, 7)
	want := []int64{0, 8, 9}
	if len(out) != len(want) {
		t.Fatalf("got %d items, want %d", len(out), len(want))
	}
	for i, it := range out {
		if it.id != want[i] {
			t.Fatalf("item %d: id %d, want %d", i, it.id, want[i])
		}
	}
	if string(out[0].payload) != "low" {
		t.Fatalf("prekeys_low item lost its payload")
	}
	if len(mergeBuffered(nil, 3)) != 0 {
		t.Fatal("nil input must give an empty result")
	}
}

func TestParseMsgIDs(t *testing.T) {
	good := "00112233445566778899aabbccddeeff"
	ids, ok := parseMsgIDs([]string{good})
	if !ok || len(ids) != 1 || len(ids[0]) != 16 {
		t.Fatalf("good id rejected: %v %v", ids, ok)
	}
	for _, bad := range []string{"", "00112233445566778899AABBCCDDEEFF", "0011", good + "00", "zz112233445566778899aabbccddeeff"} {
		if _, ok := parseMsgIDs([]string{bad}); ok {
			t.Fatalf("%q accepted", bad)
		}
	}
	many := make([]string, store.MaxAckIDs+1)
	for i := range many {
		many[i] = good
	}
	if _, ok := parseMsgIDs(many); ok {
		t.Fatal("more than MaxAckIDs accepted")
	}
	if _, ok := parseMsgIDs(many[:store.MaxAckIDs]); !ok {
		t.Fatal("exactly MaxAckIDs rejected")
	}
}

func TestFrameEncoding(t *testing.T) {
	var m map[string]any
	if err := json.Unmarshal(encodeMsg(Delivery{ID: 4411, MsgID: "ab", From: "alice", Envelope: []byte{0xfb, 0xff}, TS: 1760000000}), &m); err != nil {
		t.Fatal(err)
	}
	if m["t"] != "msg" || m["id"] != float64(4411) || m["from"] != "alice" || m["envelope"] != "-_8" || m["ts"] != float64(1760000000) {
		t.Fatalf("msg frame: %v", m)
	}
	if err := json.Unmarshal(encodePrekeysLow(12, nil), &m); err != nil {
		t.Fatal(err)
	}
	if m["t"] != "prekeys_low" || m["opk_count"] != float64(12) {
		t.Fatalf("prekeys_low frame: %v", m)
	}
	if ids, ok := m["consumed_ids"].([]any); !ok || len(ids) != 0 {
		t.Fatalf("consumed_ids must be an empty array, got %v", m["consumed_ids"])
	}
	if string(encodeError(codeBadFrame)) != `{"t":"error","code":"bad_frame"}` {
		t.Fatalf("error frame: %s", encodeError(codeBadFrame))
	}
}
