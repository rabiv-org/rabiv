//go:build linux && rabiv_integration

package phase3_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"reflect"
	"testing"

	"github.com/rabiv-org/rabiv/internal/adapters/tetragon"
	"github.com/rabiv-org/rabiv/internal/app/correlate"
	"github.com/rabiv-org/rabiv/internal/domain/artifact"
)

// TestRetainedTetragonExport replays a previously acquired native export through
// the production stream/parser. Counts are independently supplied acceptance
// evidence, never a claim of runtime completeness or absence of event loss.
func TestRetainedTetragonExport(t *testing.T) {
	path := os.Getenv("RABIV_TEST_TETRAGON_CAPTURE")
	if path == "" {
		t.Skip("retained Tetragon export not supplied")
	}
	expected := artifact.Digest{Algorithm: "sha256", Value: os.Getenv("RABIV_TEST_TETRAGON_SHA256")}
	var counts map[correlate.EventKind]uint64
	if expected.Validate() != nil || json.Unmarshal([]byte(os.Getenv("RABIV_TEST_TETRAGON_COUNTS")), &counts) != nil || len(counts) == 0 {
		t.Fatal("independently recorded capture hash and event counts are required")
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 64<<20 {
		t.Fatal("retained export must be a bounded regular file")
	}
	hash := sha256.New()
	stream, err := tetragon.NewStream(io.NopCloser(io.TeeReader(io.LimitReader(f, (64<<20)+1), hash)), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	actual := map[correlate.EventKind]uint64{}
	for {
		event, err := stream.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		actual[event.Kind]++
	}
	if hex.EncodeToString(hash.Sum(nil)) != expected.Value || !reflect.DeepEqual(actual, counts) {
		t.Fatalf("capture hash or event counts mismatch: actual=%v", actual)
	}
	t.Logf("native_export_counts=%v sha256=%s", actual, expected.Value)
}
