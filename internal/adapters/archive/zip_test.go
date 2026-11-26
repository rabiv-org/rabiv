package archive

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"testing"
)

func FuzzArchiveSelection(f *testing.F) {
	var seed bytes.Buffer
	w := zip.NewWriter(&seed)
	entry, err := w.Create("subject")
	if err != nil {
		f.Fatal(err)
	}
	if _, err = entry.Write([]byte("bounded subject")); err != nil {
		f.Fatal(err)
	}
	if err = w.Close(); err != nil {
		f.Fatal(err)
	}
	f.Add(seed.Bytes())
	f.Add([]byte("invalid zip"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64<<10 {
			t.Skip()
		}
		r := Reader{Limits: Limits{Archive: 64 << 10, Entry: 4096, Expanded: 8192, Entries: 16, Ratio: 100}}
		c, err := r.Read(context.Background(), data, []string{"subject"})
		if err == nil && (len(c.Subjects) != 1 || c.Subjects[0].Name != "subject" || len(c.Subjects[0].Bytes) > 4096) {
			t.Fatal("successful ZIP selection violated bounds or exact identity")
		}
	})
}

func zipBytes(t *testing.T, names []string, mode fs.FileMode, body string) []byte {
	t.Helper()
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	for _, name := range names {
		h := &zip.FileHeader{Name: name, Method: zip.Deflate}
		h.SetMode(mode)
		f, e := w.CreateHeader(h)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = f.Write([]byte(body)); e != nil {
			t.Fatal(e)
		}
	}
	if e := w.Close(); e != nil {
		t.Fatal(e)
	}
	return b.Bytes()
}
func TestSafeSelectionAndHostileArchives(t *testing.T) {
	r := Reader{Limits: Limits{Archive: 1 << 20, Entry: 1 << 18, Expanded: 1 << 19, Entries: 16, Ratio: 100}, ProvenanceEntry: "artifacts-metadata.json"}
	valid := zipBytes(t, []string{"dist/中 app.bin", "metadata.json"}, 0600, "actual bytes")
	c, err := r.Read(context.Background(), valid, []string{"dist/中 app.bin"})
	if err != nil || string(c.Subjects[0].Bytes) != "actual bytes" || c.Subjects[0].Name != "dist/中 app.bin" {
		t.Fatalf("selection changed: %v", err)
	}
	for _, tc := range []struct {
		name  string
		names []string
		mode  fs.FileMode
		body  string
	}{
		{"traversal", []string{"safe", "../outside"}, 0600, "x"}, {"absolute", []string{"safe", "/outside"}, 0600, "x"}, {"backslash", []string{"safe", `a\b`}, 0600, "x"}, {"duplicate", []string{"safe", "safe"}, 0600, "x"}, {"symlink", []string{"safe"}, 0600 | fs.ModeSymlink, "target"}, {"fifo", []string{"safe"}, 0600 | fs.ModeNamedPipe, "x"}, {"bomb_ratio", []string{"safe"}, 0600, strings.Repeat("0", 100000)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := r.Read(context.Background(), zipBytes(t, tc.names, tc.mode, tc.body), []string{"safe"}); err == nil {
				t.Fatal("accepted hostile ZIP")
			}
		})
	}
	if _, err := r.Read(context.Background(), valid, []string{"missing"}); err == nil {
		t.Fatal("fabricated subject")
	}
	if _, err := r.Read(context.Background(), valid, []string{"dist/中 app.bin", "dist/中 app.bin"}); err == nil {
		t.Fatal("duplicate selection")
	}
}

func TestStoredEntryWithZeroCRC(t *testing.T) {
	reader := Reader{Limits: Limits{Archive: 1024, Entry: 64, Expanded: 64, Entries: 1, Ratio: 1}}
	for _, body := range []string{"", "nonzero CRC"} {
		var buf bytes.Buffer
		z := zip.NewWriter(&buf)
		f, err := z.CreateRaw(&zip.FileHeader{Name: "selected", Method: zip.Store, CompressedSize64: uint64(len(body)), UncompressedSize64: uint64(len(body))})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
		if err := z.Close(); err != nil {
			t.Fatal(err)
		}
		_, err = reader.Read(context.Background(), buf.Bytes(), []string{"selected"})
		if (err == nil) != (body == "") {
			t.Fatalf("declared zero CRC with body %q: %v", body, err)
		}
	}
}

func BenchmarkZIPDirectoryRejection(b *testing.B) {
	var transport bytes.Buffer
	z := zip.NewWriter(&transport)
	for i := range 65537 {
		if _, err := z.CreateRaw(&zip.FileHeader{Name: fmt.Sprintf("item-%05d", i), Method: zip.Store}); err != nil {
			b.Fatal(err)
		}
	}
	if err := z.Close(); err != nil {
		b.Fatal(err)
	}
	reader := Reader{Limits: Limits{Archive: 32 << 20, Entry: 16 << 20, Expanded: 48 << 20, Entries: 1024, Ratio: 100}}
	b.SetBytes(int64(transport.Len()))
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := reader.Read(b.Context(), transport.Bytes(), []string{"item-00000"}); !errors.Is(err, ErrArchive) {
			b.Fatalf("rejected directory: %v", err)
		}
	}
}
