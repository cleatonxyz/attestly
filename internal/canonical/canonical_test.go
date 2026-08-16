package canonical

import (
	"errors"
	"strings"
	"testing"
)

func TestEncodeTable(t *testing.T) {
	tests := []struct {
		name string
		in   any
		want string
	}{
		{"nil", nil, "null"},
		{"true", true, "true"},
		{"string", "hi", `"hi"`},
		{"int", 42, "42"},
		{"int64 negative", int64(-7), "-7"},
		{"uint64 max", uint64(18446744073709551615), "18446744073709551615"},
		{"bytes as base64", []byte{0xde, 0xad}, `"3q0="`},
		{"empty map", map[string]any{}, "{}"},
		{"empty slice", []any{}, "[]"},
		{"nested", map[string]any{"b": []any{1, "x"}, "a": true}, `{"a":true,"b":[1,"x"]}`},
		{"string map", map[string]string{"z": "1", "a": "2"}, `{"a":"2","z":"1"}`},
		{"string slice", []string{"b", "a"}, `["b","a"]`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Encode(tc.in)
			if err != nil {
				t.Fatalf("Encode: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %s, want %s", got, tc.want)
			}
		})
	}
}

func TestKeyOrderIsByByteNotLocale(t *testing.T) {
	// Uppercase sorts before lowercase in byte order. A locale-aware sort would
	// put them the other way and silently change every digest.
	got, err := Encode(map[string]any{"b": 1, "A": 2, "a": 3, "B": 4})
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"A":2,"B":4,"a":3,"b":1}`; got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestStableAcrossManyEncodes(t *testing.T) {
	// Go randomizes map iteration order; the encoding must not inherit it.
	m := map[string]any{"one": 1, "two": 2, "three": 3, "four": 4, "five": 5}
	first, err := Encode(m)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 200; i++ {
		got, err := Encode(m)
		if err != nil {
			t.Fatal(err)
		}
		if got != first {
			t.Fatalf("unstable at iteration %d:\n%s\n%s", i, first, got)
		}
	}
}

func TestEscaping(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"quote", `a"b`, `"a\"b"`},
		{"backslash", `a\b`, `"a\\b"`},
		{"newline", "a\nb", `"a\nb"`},
		{"tab", "a\tb", `"a\tb"`},
		{"control", "a\x01b", `"a\u0001b"`},
		{"unicode passes through", "héllo→", `"héllo→"`},
		{"emoji passes through", "ok 🚀", `"ok 🚀"`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var b strings.Builder
			WriteString(&b, tc.in)
			if got := b.String(); got != tc.want {
				t.Fatalf("got %s, want %s", got, tc.want)
			}
		})
	}
}

func TestFloatsRejected(t *testing.T) {
	for _, v := range []any{1.5, float32(1.5), map[string]any{"x": 0.1}, []any{1.0}} {
		if _, err := Encode(v); !errors.Is(err, ErrUnsupportedType) {
			t.Fatalf("%v: got %v, want ErrUnsupportedType", v, err)
		}
	}
}

func TestUnsupportedTypesRejected(t *testing.T) {
	type custom struct{ A int }
	for _, v := range []any{custom{1}, make(chan int), map[int]string{1: "a"}} {
		if _, err := Encode(v); !errors.Is(err, ErrUnsupportedType) {
			t.Fatalf("%T: got %v, want ErrUnsupportedType", v, err)
		}
	}
}

func TestNestedErrorPropagates(t *testing.T) {
	// A float buried three levels deep must still be caught.
	deep := map[string]any{"a": []any{map[string]any{"b": 0.5}}}
	if _, err := Encode(deep); !errors.Is(err, ErrUnsupportedType) {
		t.Fatalf("got %v, want ErrUnsupportedType", err)
	}
}

func BenchmarkEncode(b *testing.B) {
	m := map[string]any{
		"subject": "base:0x1f98431c8ad98523631ae4a59f267346ea31f984",
		"horizon": int64(9),
		"nested":  map[string]any{"a": 1, "b": "two", "c": true},
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := Encode(m); err != nil {
			b.Fatal(err)
		}
	}
}
