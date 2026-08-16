package attestly

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// envelope is the wire form. It is deliberately separate from Attestation so
// the in-memory type can change without changing what is on the wire.
type envelope struct {
	Claim struct {
		Subject   string         `json:"subject"`
		Schema    string         `json:"schema"`
		Payload   map[string]any `json:"payload,omitempty"`
		IssuedAt  int64          `json:"issued_at"`
		ExpiresAt int64          `json:"expires_at"`
		Nonce     string         `json:"nonce,omitempty"`
	} `json:"claim"`
	KeyID string `json:"key_id"`
	Alg   string `json:"alg"`
	Sig   string `json:"sig"` // base64 standard encoding
}

// MarshalJSON writes the wire form: unix seconds for times, base64 for the
// signature.
func (a Attestation) MarshalJSON() ([]byte, error) {
	var e envelope
	e.Claim.Subject = a.Claim.Subject
	e.Claim.Schema = a.Claim.Schema
	e.Claim.Payload = a.Claim.Payload
	e.Claim.IssuedAt = a.Claim.IssuedAt.UTC().Unix()
	e.Claim.ExpiresAt = a.Claim.ExpiresAt.UTC().Unix()
	e.Claim.Nonce = a.Claim.Nonce
	e.KeyID = a.KeyID
	e.Alg = a.Alg
	e.Sig = base64.StdEncoding.EncodeToString(a.Sig)
	return json.Marshal(e)
}

// UnmarshalJSON reads the wire form.
//
// Payload numbers come back from encoding/json as float64, which canonicalize
// rejects on purpose. They are converted to int64 when exact, so a round trip
// of an integer payload still verifies; a genuine fraction stays a float and
// fails loudly rather than hashing to something unpredictable.
func (a *Attestation) UnmarshalJSON(b []byte) error {
	var e envelope
	if err := json.Unmarshal(b, &e); err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(e.Sig)
	if err != nil {
		return fmt.Errorf("%w: sig is not base64: %v", ErrMalformed, err)
	}
	a.Claim = Claim{
		Subject:   e.Claim.Subject,
		Schema:    e.Claim.Schema,
		Payload:   normalizeNumbers(e.Claim.Payload),
		IssuedAt:  time.Unix(e.Claim.IssuedAt, 0).UTC(),
		ExpiresAt: time.Unix(e.Claim.ExpiresAt, 0).UTC(),
		Nonce:     e.Claim.Nonce,
	}
	a.KeyID = e.KeyID
	a.Alg = e.Alg
	a.Sig = sig
	return nil
}

func normalizeNumbers(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = normalizeValue(v)
	}
	return out
}

func normalizeValue(v any) any {
	switch x := v.(type) {
	case float64:
		if i := int64(x); float64(i) == x {
			return i
		}
		return x // left as float64 so canonicalize rejects it
	case map[string]any:
		return normalizeNumbers(x)
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = normalizeValue(e)
		}
		return out
	default:
		return v
	}
}

// KeyIDFor derives a stable, short identifier from a public key. Using a
// derived id rather than a chosen one means a key cannot be published under two
// different names.
func KeyIDFor(pub ed25519.PublicKey) string {
	return hex.EncodeToString(pub[:8])
}
