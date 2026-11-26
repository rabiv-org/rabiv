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
	if err := l.validate(int64(len(data))); err != nil {
		return result, err
	}
	if err := validateSelection(names); err != nil {
		return result, err
	}
	z, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil || len(z.File) > l.Entries {
		return result, ErrArchive
	}
	seen, err := indexMembers(ctx, z.File, l, len(data))
	if err != nil {
		return result, err
	}
	for _, name := range names {
		b, e := r.readMember(seen[name])
		if e != nil {
			return result, e
		}
		result.Subjects = append(result.Subjects, ingest.SubjectBytes{Name: name, Bytes: b})
	}
	if r.ProvenanceEntry != "" && seen[r.ProvenanceEntry] != nil {
		result.ProvenancePresent = true
		result.Provenance, err = r.readMember(seen[r.ProvenanceEntry])
		if err != nil || len(result.Provenance) > 1<<20 {
			return result, ErrArchive
		}
	}
	if r.SBOMEntry != "" && seen[r.SBOMEntry] != nil {
		result.SBOMPresent = true
		result.ExistingSBOM, err = r.readMember(seen[r.SBOMEntry])
		if err != nil {
			return result, err
		}
	}
	return result, nil
}

func (l Limits) validate(size int64) error {
	if l.Archive <= 0 || l.Archive > 1<<30 || size > l.Archive || l.Entry <= 0 || l.Entry > 1<<30 || l.Expanded <= 0 || l.Expanded > 1<<30 || l.Entries <= 0 || l.Entries > 65536 || l.Ratio == 0 || l.Ratio > 1000000 {
		return ErrArchive
	}

	return nil
}

func validateSelection(names []string) error {
	selected := map[string]bool{}
	for _, name := range names {
		if !safeName(name, false) || selected[name] || (artifact.Subject{Name: name, Digest: acquire.Hash(nil)}).Validate() != nil {
			return ErrArchive
		}
		selected[name] = true
	}
	if len(selected) == 0 {
		return ErrArchive
	}

	return nil
}

func indexMembers(ctx context.Context, files []*zip.File, l Limits, archiveSize int) (map[string]*zip.File, error) {
	seen := map[string]*zip.File{}
	var total uint64
	for _, f := range files {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if seen[f.Name] != nil || !validMember(f) {
			return nil, ErrArchive
		}
		seen[f.Name] = f
		if f.UncompressedSize64 > uint64(l.Entry) || f.UncompressedSize64 > uint64(l.Expanded)-total {
			return nil, ErrArchive
		}
		total += f.UncompressedSize64
		compressed := f.CompressedSize64
		if compressed == 0 {
			compressed = 1
		}
		if compressed > uint64(archiveSize) || f.UncompressedSize64 > compressed*l.Ratio {
			return nil, ErrArchive
		}
	}

	return seen, nil
}

func validMember(f *zip.File) bool {
	if !safeName(f.Name, f.FileInfo().IsDir()) || f.Mode()&(fs.ModeSymlink|fs.ModeDevice|fs.ModeNamedPipe|fs.ModeSocket|fs.ModeCharDevice|fs.ModeIrregular) != 0 || f.Flags&1 != 0 || f.Method != zip.Store && f.Method != zip.Deflate {
		return false
	}
	if f.NonUTF8 {
		for _, b := range []byte(f.Name) {
			if b >= 128 {
				return false
			}
		}
	}

	return true
}

func (r Reader) readMember(f *zip.File) ([]byte, error) {
	if f == nil || f.FileInfo().IsDir() {
		return nil, ErrArchive
	}
	src, e := f.Open()
	if e != nil {
		return nil, ErrArchive
	}
	defer func() { _ = src.Close() }()
	b, e := acquire.ReadLimit(src, r.Limits.Entry)
	// archive/zip skips the CRC comparison for a zero CRC and no descriptor.
	if e != nil || uint64(len(b)) != f.UncompressedSize64 || f.CRC32 == 0 && crc32.ChecksumIEEE(b) != 0 {
		return nil, ErrArchive
	}
	return b, nil
}
