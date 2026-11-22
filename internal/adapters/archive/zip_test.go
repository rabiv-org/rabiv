package archive

import (
	"archive/zip"
	"bytes"
	"context"
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
