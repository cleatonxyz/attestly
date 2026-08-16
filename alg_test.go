package attestly

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"testing"
)

// fakeAlg is a stand-in for a real second algorithm (secp256k1, say). It proves
// the registry works without this package taking on a dependency.
type fakeAlg struct{}

func (fakeAlg) Name() string       { return "test-hmac" }
func (fakeAlg) PublicKeySize() int { return 0 }

func (fakeAlg) Sign(priv any, digest []byte) ([]byte, error) {
	k, ok := priv.([]byte)
	if !ok {
		return nil, ErrMalformed
	}
	m := hmac.New(sha256.New, k)
	m.Write(digest)
	return m.Sum(nil), nil
}

func (fakeAlg) Verify(pub any, digest, sig []byte) bool {
	k, ok := pub.([]byte)
	if !ok {
		return false
	}
	m := hmac.New(sha256.New, k)
	m.Write(digest)
	return hmac.Equal(m.Sum(nil), sig)
}

func TestRegisterAlgorithm(t *testing.T) {
	RegisterAlgorithm(fakeAlg{})

	found := false
	for _, name := range Algorithms() {
		if name == "test-hmac" {
			found = true
		}
	}
	if !found {
		t.Fatalf("registered algorithm missing from %v", Algorithms())
	}

	key := []byte("shared-secret")
	att, err := SignWith("test-hmac", key, "k1", sampleClaim())
	if err != nil {
		t.Fatalf("SignWith: %v", err)
	}
	if att.Alg != "test-hmac" {
		t.Fatalf("Alg = %q", att.Alg)
	}
	if err := VerifyWithKey(att, key, WithClock(att.Claim.IssuedAt)); err != nil {
		t.Fatalf("VerifyWithKey: %v", err)
	}
	if err := VerifyWithKey(att, []byte("wrong"), WithClock(att.Claim.IssuedAt)); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("got %v, want ErrBadSignature", err)
	}
}

func TestDuplicateRegistrationPanics(t *testing.T) {
	// Silently replacing an algorithm would let a linked-in package change what
	// an existing signature means, with nothing at the call site to notice.
	defer func() {
		if recover() == nil {
			t.Fatal("re-registering an algorithm must panic")
		}
	}()
	RegisterAlgorithm(ed25519Alg{})
}

func TestSignWithUnknownAlg(t *testing.T) {
	if _, err := SignWith("nope", nil, "k", sampleClaim()); !errors.Is(err, ErrUnknownAlg) {
		t.Fatalf("got %v, want ErrUnknownAlg", err)
	}
}

func TestSignWithWrongKeyType(t *testing.T) {
	if _, err := SignWith(AlgEd25519, "not-a-key", "k", sampleClaim()); !errors.Is(err, ErrMalformed) {
		t.Fatalf("got %v, want ErrMalformed", err)
	}
}

func TestEd25519VerifyAcceptsRawBytes(t *testing.T) {
	// A key read from JSON or a config file arrives as []byte, and forcing the
	// caller to convert it is friction with no safety benefit.
	priv, pub := keyFromSeed(21)
	att, err := Sign(priv, KeyIDFor(pub), sampleClaim())
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyWithKey(att, []byte(pub), WithClock(att.Claim.IssuedAt)); err != nil {
		t.Fatalf("raw bytes should verify: %v", err)
	}
	if err := VerifyWithKey(att, []byte("short"), WithClock(att.Claim.IssuedAt)); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("got %v, want ErrBadSignature", err)
	}
}
