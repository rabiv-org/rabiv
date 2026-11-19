package tetragon

import (
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/rabiv-org/rabiv/internal/app/correlate"
)

func TestNativeProfile(t *testing.T) {
	for _, tc := range []struct {
		name, kind, fields string
		want               correlate.EventKind
		valid              bool
	}{
		{"exec", "process_exec", "", correlate.ProcessExec, true},
		{"exit", "process_exit", "", correlate.ProcessExit, true},
		{"file", "process_kprobe", `,"function_name":"security_file_permission","args":[{"file_arg":{"path":"/build/out/中"}},{"int_arg":2}]`, correlate.FileWriteIntent, true},
		{"tcp", "process_kprobe", `,"function_name":"tcp_connect","args":[{"sock_arg":{"daddr":"203.0.113.7","dport":443,"protocol":"IPPROTO_TCP"}}]`, correlate.TCPConnect, true},
		{"no_index_in_wire", "process_kprobe", `,"function_name":"tcp_connect","args":[{"index":0,"sock_arg":{"daddr":"203.0.113.7","dport":443,"protocol":"IPPROTO_TCP"}}]`, correlate.TCPConnect, true},
		{"other_policy", "process_kprobe", `,"function_name":"other_hook","args":[]`, correlate.Unsupported, true},
		{"wrong_profile", "process_kprobe", `,"function_name":"security_file_permission","args":[{"int_arg":2}]`, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := fmt.Sprintf(`{"time":"2026-01-02T03:04:05.123456789Z",%q:{"process":{"exec_id":"opaque-process","docker":%q,"arguments":"not retained","pid":41}%s}}`, tc.kind, strings.Repeat("a", 23), tc.fields)
			e, err := Normalize([]byte(data), 4096)
			if (err == nil) != tc.valid || err == nil && (e.Kind != tc.want || e.At.Nanosecond() != 123456789) {
				t.Fatalf("event=%+v err=%v", e, err)
			}
		})
	}
	for _, raw := range []string{`{`, `{"time":"2026-01-02T03:04:05Z","time":"2026-01-02T03:04:06Z"}`, `{"process_exec":{}}`, `{"time":"2026-01-02T03:04:05Z","process_exec":{"process":{"exec_id":"\ud800"}}}`} {
		if _, err := Normalize([]byte(raw), 4096); err == nil {
			t.Fatal("accepted malformed record")
		}
	}
}

func TestLossReportsAndTruncatedStream(t *testing.T) {
	for _, count := range []string{`"7"`, `7`, `"0"`} {
		raw := `{"time":"2026-01-02T03:04:05Z","rate_limit_info":{"number_of_dropped_process_events":` + count + `}}`
		e, err := Normalize([]byte(raw), 4096)
		if err != nil || e.Kind != correlate.SourceLoss || e.LossCount == nil {
			t.Fatalf("loss hidden: %+v %v", e, err)
		}
	}
	s, err := NewStream(io.NopCloser(strings.NewReader("{\n")), 1024)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Next(); err == nil {
		t.Fatal("truncated JSON accepted")
	}
	if _, err = s.Next(); err != io.EOF {
		t.Fatal("stream EOF lost")
	}
}
