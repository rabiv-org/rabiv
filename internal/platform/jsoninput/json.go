// Package jsoninput validates bounded upstream JSON without silently repairing
// malformed Unicode. It is not a provenance, policy, or authenticity verifier.
package jsoninput

import (
	"bytes"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"errors"
	"io"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// ErrInvalid deliberately excludes untrusted values, URLs and credentials.
var ErrInvalid = errors.New("invalid JSON input")

// Decode rejects duplicate keys, invalid UTF-8/surrogates, excessive nesting and
// trailing values. Closed intermediate records additionally forbid null, unknown
// fields and noncanonical keys. Upstream records match exact field names but
// may have unknown fields/null.
// Callers must bound data before calling Decode.
func Decode(data []byte, out any, closed bool) error {
	if !utf8.Valid(data) {
		return ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if scan(d, data, closed, 0) != nil {
		return ErrInvalid
	}
	if _, err := d.Token(); err != io.EOF {
		return ErrInvalid
	}
	if !closed {
		// Keep legacy value semantics (including json.Number), but never let a
		// differently cased extension assign to a recognized metadata field.
		if jsonv2.Unmarshal(data, out, json.DefaultOptionsV1(), jsonv2.MatchCaseInsensitiveNames(false)) != nil {
			return ErrInvalid
		}
		return nil
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil {
		return ErrInvalid
	}
	return nil
}

func token(d *json.Decoder, data []byte) (json.Token, error) {
	start := d.InputOffset()
	t, err := d.Token()
	if err != nil {
		return nil, ErrInvalid
	}
	if _, ok := t.(string); ok {
		raw := data[start:d.InputOffset()]
		raw = raw[bytes.IndexByte(raw, '"'):]
		if err := checkEscapedString(raw); err != nil {
			return nil, err
		}
	}
	return t, nil
}

func checkEscapedString(raw []byte) error {
	for i := 1; i < len(raw)-1; i++ {
		if raw[i] != '\\' {
			continue
		}
		i++
		if raw[i] != 'u' {
			continue
		}
		code, e := strconv.ParseUint(string(raw[i+1:i+5]), 16, 16)
		if e != nil {
			return ErrInvalid
		}
		i += 4
		if !utf16.IsSurrogate(rune(code)) {
			continue
		}
		if code >= 0xdc00 || i+7 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
			return ErrInvalid
		}
		low, e := strconv.ParseUint(string(raw[i+3:i+7]), 16, 16)
		if e != nil || utf16.DecodeRune(rune(code), rune(low)) == utf8.RuneError {
			return ErrInvalid
		}
		i += 6
	}
	return nil
}

func scan(d *json.Decoder, data []byte, closed bool, depth int) error {
	if depth > 64 {
		return ErrInvalid
	}
	t, err := token(d, data)
	if err != nil || closed && t == nil {
		return ErrInvalid
	}
	switch t {
	case json.Delim('{'):
		return scanObject(d, data, closed, depth)
	case json.Delim('['):
		return scanArray(d, data, closed, depth)
	case json.Delim('}'), json.Delim(']'):
		return ErrInvalid
	}
	return nil
}

func scanObject(d *json.Decoder, data []byte, closed bool, depth int) error {
	seen := map[string]bool{}
	for d.More() {
		k, err := token(d, data)
		key, ok := k.(string)
		if err != nil || !ok || seen[key] || closed && !canonical(key) {
			return ErrInvalid
		}
		seen[key] = true
		if scan(d, data, closed, depth+1) != nil {
			return ErrInvalid
		}
	}
	end, err := d.Token()
	if err != nil || end != json.Delim('}') {
		return ErrInvalid
	}
	return nil
}

func scanArray(d *json.Decoder, data []byte, closed bool, depth int) error {
	for d.More() {
		if scan(d, data, closed, depth+1) != nil {
			return ErrInvalid
		}
	}
	end, err := d.Token()
	if err != nil || end != json.Delim(']') {
		return ErrInvalid
	}
	return nil
}

func canonical(s string) bool {
	if s == "" || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for _, r := range s {
		if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyz0123456789_", r) {
			return false
		}
	}
	return true
}
