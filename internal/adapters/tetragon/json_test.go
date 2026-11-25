package tetragon

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/rabiv-org/rabiv/internal/app/correlate"
)

func FuzzNormalize(f *testing.F) {
	for _, raw := range []string{`{"time":"2026-01-02T03:04:05Z","process_exec":{"process":{"exec_id":"exec"}}}`, `{"time":"2026-01-02T03:04:05Z","rate_limit_info":{"number_of_dropped_process_events":"7"}}`, `{`, `{"time":null}`} {
		f.Add([]byte(raw))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 8192 {
			t.Skip()
		}
		e, err := Normalize(data, 8192)
		if err != nil {
			return
		}
		if e.At.IsZero() || e.Source != "TETRAGON" || (e.Kind == correlate.SourceLoss) != (e.LossCount != nil) {
			t.Fatal("accepted event violated source/time/loss representation")
		}
	})
}

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
		{"conflicting_file", "process_kprobe", `,"function_name":"security_file_permission","args":[{"file_arg":{"path":"/out"},"int_arg":7},{"int_arg":2}]`, "", false},
		{"conflicting_socket", "process_kprobe", `,"function_name":"tcp_connect","args":[{"sock_arg":{"daddr":"203.0.113.7","dport":443,"protocol":"IPPROTO_TCP"},"string_arg":"conflict"}]`, "", false},
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

func TestProcessIdentityBounds(t *testing.T) {
	for _, event := range []string{
		`"process_exec":{"process":{"exec_id":"exec"},"parent":{"exec_id":"%s"}}`,
		`"process_kprobe":{"process":{"exec_id":"exec"},"parent":{"exec_id":"%s"},"function_name":"security_file_permission","args":[{"file_arg":{"path":"/file"}},{"int_arg":4}]}`,
		`"process_kprobe":{"process":{"exec_id":"%s"},"function_name":"security_file_permission","args":[{"file_arg":{"path":"/file"}},{"int_arg":4}]}`,
	} {
		data := fmt.Appendf(nil, `{"time":"2026-01-02T03:04:05Z",`+event+`}`, strings.Repeat("x", 1025))
		if _, err := Normalize(data, 4096); !errors.Is(err, ErrRecord) {
			t.Fatalf("oversized ID accepted: %v", err)
		}
	}
}

type failingReader struct{ err error }

func (r failingReader) Read([]byte) (int, error) { return 0, r.err }

func TestStreamReadFailureIsNotTruncation(t *testing.T) {
	readErr := errors.New("test transport failure")
	s, err := NewStream(io.NopCloser(failingReader{readErr}), 4096)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.Next()
	if !errors.Is(err, readErr) || errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("read failure misclassified: %v", err)
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
