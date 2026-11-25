// Package archive performs bounded ZIP selection without extracting entry names
// into paths. It must run inside the isolated uncredentialed Worker invocation.
package archive

import (
	"archive/zip"
	"bytes"
	"context"
	"hash/crc32"
	"io/fs"
	"path"
	"strings"
	"unicode/utf8"

	v1 "github.com/rabiv-org/rabiv/contracts/v1"
	"github.com/rabiv-org/rabiv/internal/app/acquire"
	"github.com/rabiv-org/rabiv/internal/app/ingest"
	"github.com/rabiv-org/rabiv/internal/domain/artifact"
)

var ErrArchive = &acquire.InputError{Code: v1.InvalidInput}

type Limits struct {
	Archive, Entry, Expanded int64
	Entries                  int
	Ratio                    uint64
}
type Reader struct {
	Limits                     Limits
	ProvenanceEntry, SBOMEntry string
}

func safeName(name string, dir bool) bool {
	if name == "" || !utf8.ValidString(name) || strings.ContainsAny(name, "\\\x00") || strings.HasPrefix(name, "/") || len(name) > 1 && name[1] == ':' {
		return false
	}
	if dir {
		name = strings.TrimSuffix(name, "/")
	}
	return name != "." && name != ".." && path.Clean(name) == name && !strings.HasPrefix(name, "../")
}

// Read validates every central-directory entry (also unselected links/paths),
// then CRC-checks and hashes the selected payload at the Worker boundary. No
// extract-all, symlink creation, external URL or subject-derived path is used.
func (r Reader) Read(ctx context.Context, data []byte, names []string) (ingest.Contents, error) {
	result := ingest.Contents{Subjects: []ingest.SubjectBytes{}}
	l := r.Limits
	if l.Archive <= 0 || l.Archive > 1<<30 || int64(len(data)) > l.Archive || l.Entry <= 0 || l.Entry > 1<<30 || l.Expanded <= 0 || l.Expanded > 1<<30 || l.Entries <= 0 || l.Entries > 65536 || l.Ratio == 0 || l.Ratio > 1000000 {
		return result, ErrArchive
	}
	selected := map[string]bool{}
	for _, name := range names {
		if !safeName(name, false) || selected[name] || (artifact.Subject{Name: name, Digest: acquire.Hash(nil)}).Validate() != nil {
			return result, ErrArchive
		}
		selected[name] = true
	}
	if len(selected) == 0 {
		return result, ErrArchive
	}
	z, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil || len(z.File) > l.Entries {
		return result, ErrArchive
	}
	seen := map[string]*zip.File{}
	var total uint64
	for _, f := range z.File {
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		if seen[f.Name] != nil || !safeName(f.Name, f.FileInfo().IsDir()) || f.Mode()&(fs.ModeSymlink|fs.ModeDevice|fs.ModeNamedPipe|fs.ModeSocket|fs.ModeCharDevice|fs.ModeIrregular) != 0 || f.Flags&1 != 0 || f.Method != zip.Store && f.Method != zip.Deflate {
			return result, ErrArchive
		}
		if f.NonUTF8 {
			for _, b := range []byte(f.Name) {
				if b >= 128 {
					return result, ErrArchive
				}
			}
		}
		seen[f.Name] = f
		if f.UncompressedSize64 > uint64(l.Entry) || f.UncompressedSize64 > uint64(l.Expanded)-total {
			return result, ErrArchive
		}
		total += f.UncompressedSize64
		compressed := f.CompressedSize64
		if compressed == 0 {
			compressed = 1
		}
		if compressed > uint64(len(data)) || f.UncompressedSize64 > compressed*l.Ratio {
			return result, ErrArchive
		}
	}
	read := func(name string) ([]byte, error) {
		f := seen[name]
		if f == nil || f.FileInfo().IsDir() {
			return nil, ErrArchive
		}
		src, e := f.Open()
		if e != nil {
			return nil, ErrArchive
		}
		defer func() { _ = src.Close() }()
		b, e := acquire.ReadLimit(src, l.Entry)
		// archive/zip skips the CRC comparison for a zero CRC and no descriptor.
		if e != nil || uint64(len(b)) != f.UncompressedSize64 || f.CRC32 == 0 && crc32.ChecksumIEEE(b) != 0 {
			return nil, ErrArchive
		}
		return b, nil
	}
	for _, name := range names {
		b, e := read(name)
		if e != nil {
			return result, e
		}
		result.Subjects = append(result.Subjects, ingest.SubjectBytes{Name: name, Bytes: b})
	}
	if r.ProvenanceEntry != "" && seen[r.ProvenanceEntry] != nil {
		result.ProvenancePresent = true
		result.Provenance, err = read(r.ProvenanceEntry)
		if err != nil || len(result.Provenance) > 1<<20 {
			return result, ErrArchive
		}
	}
	if r.SBOMEntry != "" && seen[r.SBOMEntry] != nil {
		result.SBOMPresent = true
		result.ExistingSBOM, err = read(r.SBOMEntry)
		if err != nil {
			return result, err
		}
	}
	return result, nil
}
