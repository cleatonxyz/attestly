// Package attestly signs and verifies short-lived off-chain claims.
//
// A [Claim] says something about a subject, valid until an expiry. Signing it
// produces an [Attestation] that anybody holding the public key can check
// without contacting the issuer. The digest is built from a canonical encoding,
// so an independent implementation reproduces the same bytes.
//
// Start with [Sign] and [Verify] for ed25519. For key rotation use a [KeyRing]
// with [VerifyWithRing]; for many attestations at once use [VerifyBatch]; to
// add an algorithm without this package taking on the dependency, implement
// [Algorithm] and call [RegisterAlgorithm].
package attestly

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cleatonxyz/attestly/internal/canonical"
)

// Domain separates attestly digests from any other use of the same key.
// It is part of the hashed bytes, so changing it invalidates every signature.
const Domain = "attestly/v1"

// AlgEd25519 is the built-in algorithm. The field exists on every attestation
// so a verifier written against v0.1 rejects a future algorithm loudly instead
// of silently accepting bytes it does not understand.
const AlgEd25519 = "ed25519"

var (
	// ErrExpired means the attestation was valid but its expiry has passed.
	ErrExpired = errors.New("attestly: attestation expired")
	// ErrNotYetValid means IssuedAt is in the future relative to the clock.
	ErrNotYetValid = errors.New("attestly: attestation not yet valid")
	// ErrBadSignature means the signature does not match key and digest.
	ErrBadSignature = errors.New("attestly: signature does not verify")
	// ErrUnknownAlg means the attestation names an algorithm this build cannot check.
	ErrUnknownAlg = errors.New("attestly: unknown signature algorithm")
	// ErrMalformed means required fields are missing or inconsistent.
	ErrMalformed = errors.New("attestly: malformed attestation")
	// ErrUnsupportedType means the payload holds a value with no canonical form.
	ErrUnsupportedType = canonical.ErrUnsupportedType
)

// Claim is the signed statement. Every field is covered by the digest.
type Claim struct {
	// Subject identifies what the claim is about, e.g. a chain-qualified address.
	Subject string `json:"subject"`
	// Schema names the shape of Payload so consumers can branch safely.
	Schema string `json:"schema"`
	// Payload holds the claim body. Values may be string, bool, integer, []byte,
	// nil, []any, or map[string]any. Floats are rejected; see the canonical
	// encoding for why.
	Payload map[string]any `json:"payload"`
	// IssuedAt and ExpiresAt bound validity. Both are compared at second
	// precision because that is what the canonical encoding preserves.
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	// Nonce makes two otherwise identical claims distinguishable. Optional.
	Nonce string `json:"nonce,omitempty"`
}

// TTL is how long the claim is valid for.
func (c Claim) TTL() time.Duration { return c.ExpiresAt.Sub(c.IssuedAt) }

// Attestation is a Claim plus the signature over its digest.
type Attestation struct {
	Claim Claim  `json:"claim"`
	KeyID string `json:"key_id"`
	Alg   string `json:"alg"`
	Sig   []byte `json:"sig"`
}

// Canonical returns the exact bytes that get hashed. Two implementations that
// agree on these bytes agree on every signature, which is why this is exported:
// a verifier in another language can be tested against it directly.
func (c Claim) Canonical() ([]byte, error) {
	if c.Subject == "" {
		return nil, fmt.Errorf("%w: empty subject", ErrMalformed)
	}
	if c.ExpiresAt.Before(c.IssuedAt) {
		return nil, fmt.Errorf("%w: expires_at before issued_at", ErrMalformed)
	}
	// Build an ordinary map so claim fields and payload keys sort under one rule.
	m := map[string]any{
		"subject":    c.Subject,
		"schema":     c.Schema,
		"issued_at":  c.IssuedAt.UTC().Unix(),
		"expires_at": c.ExpiresAt.UTC().Unix(),
	}
	if c.Payload != nil {
		m["payload"] = map[string]any(c.Payload)
	}
	if c.Nonce != "" {
		m["nonce"] = c.Nonce
	}

	var b strings.Builder
	b.WriteString(Domain)
	b.WriteByte('\n')
	if err := canonical.Write(&b, m); err != nil {
		return nil, err
	}
	return []byte(b.String()), nil
}

// Digest is the SHA-256 of the canonical bytes: what actually gets signed.
func (c Claim) Digest() ([32]byte, error) {
	b, err := c.Canonical()
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(b), nil
}

// Sign produces an ed25519 Attestation for the claim. keyID is opaque to this
// package and exists so a verifier can pick the right public key during
// rotation.
func Sign(priv ed25519.PrivateKey, keyID string, c Claim) (*Attestation, error) {
	return SignWith(AlgEd25519, priv, keyID, c)
}

// SignWith signs using a registered algorithm.
func SignWith(alg string, priv any, keyID string, c Claim) (*Attestation, error) {
	a, err := lookupAlg(alg)
	if err != nil {
		return nil, err
	}
	d, err := c.Digest()
	if err != nil {
		return nil, err
	}
	sig, err := a.Sign(priv, d[:])
	if err != nil {
		return nil, err
	}
	return &Attestation{Claim: c, KeyID: keyID, Alg: alg, Sig: sig}, nil
}

// VerifyOption adjusts verification.
type VerifyOption func(*verifyOpts)

type verifyOpts struct {
	now     time.Time
	skew    time.Duration
	stale   bool
	subject string
	schema  string
	maxTTL  time.Duration
}

// WithClock verifies against a fixed time instead of time.Now. Tests and
// replays need this; so does checking what a consumer would have seen.
func WithClock(t time.Time) VerifyOption {
	return func(o *verifyOpts) { o.now = t }
}

// WithSkew tolerates clock drift on both bounds.
func WithSkew(d time.Duration) VerifyOption {
	return func(o *verifyOpts) { o.skew = d }
}

// AllowExpired checks the signature but not the time bounds. Use it to audit
// historical attestations, never to decide something now.
func AllowExpired() VerifyOption {
	return func(o *verifyOpts) { o.stale = true }
}

// ExpectSubject rejects an attestation about a different subject.
//
// Worth setting whenever the subject is known in advance: a validly signed,
// unexpired attestation about some *other* pool is exactly what a substitution
// attack looks like, and the signature check alone will not notice.
func ExpectSubject(subject string) VerifyOption {
	return func(o *verifyOpts) { o.subject = subject }
}

// ExpectSchema rejects an attestation with a different schema, so a consumer
// cannot be handed a payload shaped for someone else.
func ExpectSchema(schema string) VerifyOption {
	return func(o *verifyOpts) { o.schema = schema }
}

// MaxTTL rejects an attestation whose validity window is longer than d.
//
// A signer that issues a ten-year attestation has effectively disabled expiry;
// a consumer that cares can refuse to accept one.
func MaxTTL(d time.Duration) VerifyOption {
	return func(o *verifyOpts) { o.maxTTL = d }
}

// Verify checks an ed25519 attestation.
//
// Callers should compare the returned error with errors.Is: an expired
// attestation is a different situation from a forged one, and collapsing the
// two loses the distinction that matters operationally.
func Verify(a *Attestation, pub ed25519.PublicKey, opts ...VerifyOption) error {
	return VerifyWithKey(a, pub, opts...)
}

// VerifyWithKey checks an attestation against a public key of whatever type its
// algorithm expects.
func VerifyWithKey(a *Attestation, pub any, opts ...VerifyOption) error {
	if a == nil {
		return fmt.Errorf("%w: nil attestation", ErrMalformed)
	}
	o := verifyOpts{now: time.Now()}
	for _, fn := range opts {
		fn(&o)
	}

	alg, err := lookupAlg(a.Alg)
	if err != nil {
		return err
	}
	d, err := a.Claim.Digest()
	if err != nil {
		return err
	}
	// Signature first: a forged claim should not be reported as merely expired,
	// because a caller could retry that past with AllowExpired.
	if !alg.Verify(pub, d[:], a.Sig) {
		return ErrBadSignature
	}

	if o.subject != "" && a.Claim.Subject != o.subject {
		return fmt.Errorf("%w: subject %q, expected %q", ErrMalformed, a.Claim.Subject, o.subject)
	}
	if o.schema != "" && a.Claim.Schema != o.schema {
		return fmt.Errorf("%w: schema %q, expected %q", ErrMalformed, a.Claim.Schema, o.schema)
	}
	if o.maxTTL > 0 && a.Claim.TTL() > o.maxTTL {
		return fmt.Errorf("%w: ttl %s exceeds limit %s", ErrMalformed, a.Claim.TTL(), o.maxTTL)
	}

	if o.stale {
		return nil
	}
	if o.now.Add(o.skew).Before(a.Claim.IssuedAt) {
		return fmt.Errorf("%w: issued_at %s", ErrNotYetValid, a.Claim.IssuedAt.UTC().Format(time.RFC3339))
	}
	if o.now.Add(-o.skew).After(a.Claim.ExpiresAt) {
		return fmt.Errorf("%w: expires_at %s", ErrExpired, a.Claim.ExpiresAt.UTC().Format(time.RFC3339))
	}
	return nil
}

// Valid is Verify reduced to a bool, for call sites that genuinely do not care
// why. Prefer Verify: "why" is usually the interesting part.
func Valid(a *Attestation, pub any, opts ...VerifyOption) bool {
	return VerifyWithKey(a, pub, opts...) == nil
}
