// Package canonical encodes values into a single, reproducible byte form.
//
// It lives in internal/ because it is an implementation detail of the digest:
// callers should depend on what a claim hashes to, not on how it is spelled.
// Keeping it unexported also means the encoding can be extended without it
// becoming part of anybody's API surface.
package canonical

import (
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// ErrUnsupportedType is returned for a value with no single canonical form.
var ErrUnsupportedType = errors.New("unsupported payload type")

// Encode returns the canonical encoding of v.
func Encode(v any) (string, error) {
	var b strings.Builder
	if err := Write(&b, v); err != nil {
		return "", err
	}
	return b.String(), nil
}

// Write appends the canonical encoding of v to buf: object keys sorted by UTF-8
// byte order, no insignificant whitespace, and no floating point.
//
// Floats are rejected on purpose. A float64 has no single agreed decimal form
// across languages, so two correct implementations can disagree on the bytes
// they hash. Since the point of this encoding is that an independent verifier
// reproduces our digest exactly, an ambiguous encoding is worse than a missing
// feature. Callers pass decimals as strings or as fixed-point integers.
func Write(buf *strings.Builder, v any) error {
	switch x := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		buf.WriteString(strconv.FormatBool(x))
	case string:
		WriteString(buf, x)
	case int:
		buf.WriteString(strconv.FormatInt(int64(x), 10))
	case int8:
		buf.WriteString(strconv.FormatInt(int64(x), 10))
	case int16:
		buf.WriteString(strconv.FormatInt(int64(x), 10))
	case int32:
		buf.WriteString(strconv.FormatInt(int64(x), 10))
	case int64:
		buf.WriteString(strconv.FormatInt(x, 10))
	case uint:
		buf.WriteString(strconv.FormatUint(uint64(x), 10))
	case uint8:
		buf.WriteString(strconv.FormatUint(uint64(x), 10))
	case uint16:
		buf.WriteString(strconv.FormatUint(uint64(x), 10))
	case uint32:
		buf.WriteString(strconv.FormatUint(uint64(x), 10))
	case uint64:
		buf.WriteString(strconv.FormatUint(x, 10))
	case []byte:
		// Bytes travel as base64 strings so the encoding stays valid JSON.
		WriteString(buf, base64.StdEncoding.EncodeToString(x))
	case []any:
		buf.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := Write(buf, e); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case []string:
		buf.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			WriteString(buf, e)
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			WriteString(buf, k)
			buf.WriteByte(':')
			if err := Write(buf, x[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	case map[string]string:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			WriteString(buf, k)
			buf.WriteByte(':')
			WriteString(buf, x[k])
		}
		buf.WriteByte('}')
	case float32, float64:
		return fmt.Errorf("%w: float has no canonical form, pass a string or a fixed-point integer", ErrUnsupportedType)
	default:
		return fmt.Errorf("%w: %T", ErrUnsupportedType, v)
	}
	return nil
}

// WriteString escapes exactly the characters JSON requires and nothing more,
// so the same input always produces the same bytes.
func WriteString(buf *strings.Builder, s string) {
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		default:
			if r < 0x20 {
				fmt.Fprintf(buf, `\u%04x`, r)
			} else {
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
}
