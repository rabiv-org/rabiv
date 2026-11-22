package jsoninput

import (
	"encoding/json"
	"testing"
	"unicode/utf8"
)

func FuzzDecode(f *testing.F) {
	for _, raw := range []string{`{"name":"中/😀/�"}`, `{"name":"\ud800"}`, `{"name":"a","name":"b"}`, `{"name":null}`, `{`, `[]`} {
		f.Add([]byte(raw), true)
		f.Add([]byte(raw), false)
	}
	f.Fuzz(func(t *testing.T, data []byte, closed bool) {
		if len(data) > 8192 {
			t.Skip()
		}
		var v struct {
			Name string `json:"name"`
		}
		if Decode(data, &v, closed) != nil {
			return
		}
		if !utf8.ValidString(v.Name) {
			t.Fatal("invalid decoded identity")
		}
		encoded, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		var roundTrip struct {
			Name string `json:"name"`
		}
		if Decode(encoded, &roundTrip, true) != nil || roundTrip.Name != v.Name {
			t.Fatal("valid identity changed during strict round trip")
		}
	})
}

func TestDecode(t *testing.T) {
	for _, tc := range []struct {
		name, input   string
		closed, valid bool
	}{
		{"raw_unicode", `{"name":"中/😀/�"}`, true, true},
		{"escaped_unicode", `{"name":"\u4e2d/\ud83d\ude00/\ufffd"}`, true, true},
		{"literal_slash", `{"name":"\\ud800"}`, true, true},
		{"high_surrogate", `{"name":"\ud800"}`, false, false},
		{"low_surrogate", `{"name":"\udc00"}`, false, false},
		{"bad_pair", `{"name":"\ud800\ud801"}`, false, false},
		{"duplicate", `{"name":"a","name":"b"}`, false, false},
		{"alias", `{"Name":"a"}`, true, false},
		{"unknown", `{"other":"a"}`, true, false},
		{"upstream_unknown", `{"other":null}`, false, true},
		{"null", `{"name":null}`, true, false},
		{"trailing", `{"name":"a"} {}`, false, false},
		{"bad_utf8", "{\"name\":\"\xff\"}", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var v struct {
				Name string `json:"name"`
			}
			err := Decode([]byte(tc.input), &v, tc.closed)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v err=%v", tc.valid, err)
			}
		})
	}
}
