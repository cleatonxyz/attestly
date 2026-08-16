package attestly

import (
	"crypto/ed25519"
	"fmt"
	"sort"
	"sync"
)

// Algorithm signs and verifies a digest.
//
// It exists so secp256k1 — or anything else — can be added without this package
// taking on the dependency. A verifier built today rejects an algorithm it does
// not know rather than guessing, which is why Attestation carries the name.
type Algorithm interface {
	// Name is the value written to Attestation.Alg.
	Name() string
	// Sign returns a signature over the 32-byte digest.
	Sign(priv any, digest []byte) ([]byte, error)
	// Verify reports whether sig is valid for digest under pub.
	Verify(pub any, digest, sig []byte) bool
	// PublicKeySize is the expected length of an encoded public key, or 0 when
	// the algorithm does not have a fixed size.
	PublicKeySize() int
}

var (
	algMu sync.RWMutex
	algs  = map[string]Algorithm{AlgEd25519: ed25519Alg{}}
)

// RegisterAlgorithm makes an algorithm available to Sign and Verify.
//
// It panics on a duplicate name. Silently replacing an algorithm would let a
// linked-in package change what an existing signature means, which is not a
// failure anybody would find by reading the call site.
func RegisterAlgorithm(a Algorithm) {
	algMu.Lock()
	defer algMu.Unlock()
	if _, exists := algs[a.Name()]; exists {
		panic("attestly: algorithm already registered: " + a.Name())
	}
	algs[a.Name()] = a
}

// Algorithms lists the registered algorithm names, sorted.
func Algorithms() []string {
	algMu.RLock()
	defer algMu.RUnlock()
	out := make([]string, 0, len(algs))
	for name := range algs {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func lookupAlg(name string) (Algorithm, error) {
	algMu.RLock()
	defer algMu.RUnlock()
	a, ok := algs[name]
	if !ok {
		return nil, fmt.Errorf("%w: %q (registered: %v)", ErrUnknownAlg, name, algNamesLocked())
	}
	return a, nil
}

func algNamesLocked() []string {
	out := make([]string, 0, len(algs))
	for name := range algs {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// ed25519Alg is the built-in algorithm.
type ed25519Alg struct{}

func (ed25519Alg) Name() string { return AlgEd25519 }

func (ed25519Alg) PublicKeySize() int { return ed25519.PublicKeySize }

func (ed25519Alg) Sign(priv any, digest []byte) ([]byte, error) {
	k, ok := priv.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%w: ed25519 needs an ed25519.PrivateKey, got %T", ErrMalformed, priv)
	}
	if len(k) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: bad private key size %d", ErrMalformed, len(k))
	}
	return ed25519.Sign(k, digest), nil
}

func (ed25519Alg) Verify(pub any, digest, sig []byte) bool {
	k, ok := pub.(ed25519.PublicKey)
	if !ok {
		b, isBytes := pub.([]byte)
		if !isBytes {
			return false
		}
		k = ed25519.PublicKey(b)
	}
	if len(k) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(k, digest, sig)
}
