package attestly

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

var (
	// ErrUnknownKeyID means the attestation names a key the ring does not hold.
	ErrUnknownKeyID = errors.New("attestly: unknown key id")
	// ErrKeyRetired means the key was valid once but not when the attestation
	// was issued.
	ErrKeyRetired = errors.New("attestly: key was not active when issued")
)

// KeyEntry is one public key with the window in which it was trusted.
type KeyEntry struct {
	KeyID string
	Alg   string
	// Public is the algorithm's public key type, e.g. ed25519.PublicKey.
	Public any
	// NotBefore and NotAfter bound the key's active period. A zero NotAfter
	// means still active.
	NotBefore time.Time
	NotAfter  time.Time
}

// active reports whether the key was trusted at t.
func (k KeyEntry) active(t time.Time) bool {
	if !k.NotBefore.IsZero() && t.Before(k.NotBefore) {
		return false
	}
	if !k.NotAfter.IsZero() && t.After(k.NotAfter) {
		return false
	}
	return true
}

// KeyRing resolves key ids to public keys, and remembers when each key was
// trusted.
//
// Rotation is the reason this exists. Once a key is retired, attestations it
// signed while active must keep verifying — a published record that stops
// verifying at rotation is worthless — while anything it signs afterwards must
// not. Checking the key against the claim's IssuedAt gets both.
//
// A KeyRing is safe for concurrent use.
type KeyRing struct {
	mu   sync.RWMutex
	keys map[string]KeyEntry
}

// NewKeyRing returns an empty ring.
func NewKeyRing() *KeyRing { return &KeyRing{keys: make(map[string]KeyEntry)} }

// Add registers a key. It replaces any entry with the same id.
func (r *KeyRing) Add(e KeyEntry) error {
	if e.KeyID == "" {
		return fmt.Errorf("%w: empty key id", ErrMalformed)
	}
	if e.Alg == "" {
		e.Alg = AlgEd25519
	}
	if _, err := lookupAlg(e.Alg); err != nil {
		return err
	}
	if !e.NotAfter.IsZero() && !e.NotBefore.IsZero() && e.NotAfter.Before(e.NotBefore) {
		return fmt.Errorf("%w: key %s retires before it starts", ErrMalformed, e.KeyID)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.keys[e.KeyID] = e
	return nil
}

// AddEd25519 registers an ed25519 key that is active from now on, deriving the
// key id the same way Sign does.
func (r *KeyRing) AddEd25519(pub ed25519.PublicKey) error {
	return r.Add(KeyEntry{KeyID: KeyIDFor(pub), Alg: AlgEd25519, Public: pub})
}

// Retire marks a key as no longer trusted for anything issued after t.
func (r *KeyRing) Retire(keyID string, t time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.keys[keyID]
	if !ok {
		return fmt.Errorf("%w: %s", ErrUnknownKeyID, keyID)
	}
	e.NotAfter = t
	r.keys[keyID] = e
	return nil
}

// Get returns the entry for a key id.
func (r *KeyRing) Get(keyID string) (KeyEntry, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.keys[keyID]
	return e, ok
}

// KeyIDs lists the registered key ids, sorted.
func (r *KeyRing) KeyIDs() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.keys))
	for id := range r.keys {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// Len is the number of keys held.
func (r *KeyRing) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.keys)
}

// VerifyWithRing resolves the attestation's key id in the ring and verifies it.
//
// The key must have been active when the claim was issued, not merely present
// in the ring. A retired key that keeps verifying new attestations makes
// rotation ceremonial.
func VerifyWithRing(a *Attestation, ring *KeyRing, opts ...VerifyOption) error {
	if a == nil {
		return fmt.Errorf("%w: nil attestation", ErrMalformed)
	}
	if ring == nil {
		return fmt.Errorf("%w: nil key ring", ErrMalformed)
	}
	entry, ok := ring.Get(a.KeyID)
	if !ok {
		return fmt.Errorf("%w: %q", ErrUnknownKeyID, a.KeyID)
	}
	if entry.Alg != a.Alg {
		return fmt.Errorf("%w: key %s is %s, attestation claims %s", ErrUnknownAlg, a.KeyID, entry.Alg, a.Alg)
	}
	if !entry.active(a.Claim.IssuedAt) {
		return fmt.Errorf("%w: key %s, issued %s", ErrKeyRetired, a.KeyID,
			a.Claim.IssuedAt.UTC().Format(time.RFC3339))
	}
	return VerifyWithKey(a, entry.Public, opts...)
}

// KeyIDForBytes derives a key id from a raw encoded public key.
func KeyIDForBytes(pub []byte) string {
	if len(pub) < 8 {
		return hex.EncodeToString(pub)
	}
	return hex.EncodeToString(pub[:8])
}
