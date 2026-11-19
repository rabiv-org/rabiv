package jsoninput

import "testing"

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
