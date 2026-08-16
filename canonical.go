package attestly

import (
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// ErrUnsupportedType is returned when a payload contains a value that has no
// single canonical byte representation.
var ErrUnsupportedType = errors.New("attestly: unsupported payload type")

// canonicalize writes v to buf in a deterministic form: object keys sorted by
// their UTF-8 byte order, no insignificant whitespace, and no floating point.
//
// Floats are rejected on purpose. A float64 has no single agreed decimal form
// across languages, so two correct implementations can disagree on the bytes
// they hash. Since the whole point of this package is that an independent
// verifier reproduces our digest exactly, an ambiguous encoding is worse than a
// missing feature. Callers pass decimals as strings or as fixed-point integers.
func canonicalize(buf *strings.Builder, v any) error {
	switch x := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		buf.WriteString(strconv.FormatBool(x))
	case string:
		writeCanonicalString(buf, x)
	case int:
		buf.WriteString(strconv.FormatInt(int64(x), 10))
	case int64:
		buf.WriteString(strconv.FormatInt(x, 10))
	case uint64:
		buf.WriteString(strconv.FormatUint(x, 10))
	case []byte:
		// Bytes travel as base64 strings so the encoding stays valid JSON.
		writeCanonicalString(buf, base64.StdEncoding.EncodeToString(x))
	case []any:
		buf.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := canonicalize(buf, e); err != nil {
				return err
			}
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
			writeCanonicalString(buf, k)
			buf.WriteByte(':')
			if err := canonicalize(buf, x[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	case float32, float64:
		return fmt.Errorf("%w: float has no canonical form, pass a string or a fixed-point integer", ErrUnsupportedType)
	default:
		return fmt.Errorf("%w: %T", ErrUnsupportedType, v)
	}
	return nil
}

// writeCanonicalString escapes exactly the characters JSON requires and nothing
// more, so the same input always produces the same bytes.
func writeCanonicalString(buf *strings.Builder, s string) {
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
				buf.WriteString(fmt.Sprintf(`\u%04x`, r))
			} else {
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
}
