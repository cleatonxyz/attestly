package attestly

import (
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"
)

func keyFromSeed(b byte) (ed25519.PrivateKey, ed25519.PublicKey) {
	priv := ed25519.NewKeyFromSeed([]byte(strings.Repeat(string([]byte{b}), ed25519.SeedSize)))
	return priv, priv.Public().(ed25519.PublicKey)
}

func TestKeyRingResolvesByKeyID(t *testing.T) {
	priv, pub := keyFromSeed(1)
	ring := NewKeyRing()
	if err := ring.AddEd25519(pub); err != nil {
		t.Fatalf("AddEd25519: %v", err)
	}

	att, err := Sign(priv, KeyIDFor(pub), sampleClaim())
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyWithRing(att, ring, WithClock(att.Claim.IssuedAt)); err != nil {
		t.Fatalf("VerifyWithRing: %v", err)
	}
	if ring.Len() != 1 || len(ring.KeyIDs()) != 1 {
		t.Fatalf("ring should hold one key, got %d", ring.Len())
	}
}

func TestKeyRingRejectsUnknownKeyID(t *testing.T) {
	priv, pub := keyFromSeed(1)
	ring := NewKeyRing()
	// Ring holds a different key.
	_, otherPub := keyFromSeed(2)
	if err := ring.AddEd25519(otherPub); err != nil {
		t.Fatal(err)
	}

	att, err := Sign(priv, KeyIDFor(pub), sampleClaim())
	if err != nil {
		t.Fatal(err)
	}
	err = VerifyWithRing(att, ring, WithClock(att.Claim.IssuedAt))
	if !errors.Is(err, ErrUnknownKeyID) {
		t.Fatalf("got %v, want ErrUnknownKeyID", err)
	}
}

func TestRotationKeepsOldAttestationsValid(t *testing.T) {
	// The point of rotation support: a published record must not stop verifying
	// the moment a key is retired, or the whole track record evaporates.
	priv, pub := keyFromSeed(3)
	issued := time.Unix(1_755_000_000, 0).UTC()

	claim := sampleClaim()
	claim.IssuedAt = issued
	claim.ExpiresAt = issued.Add(24 * time.Hour)

	att, err := Sign(priv, KeyIDFor(pub), claim)
	if err != nil {
		t.Fatal(err)
	}

	ring := NewKeyRing()
	if err := ring.AddEd25519(pub); err != nil {
		t.Fatal(err)
	}
	// Retire the key an hour after this attestation was issued.
	if err := ring.Retire(KeyIDFor(pub), issued.Add(time.Hour)); err != nil {
		t.Fatalf("Retire: %v", err)
	}

	if err := VerifyWithRing(att, ring, WithClock(issued.Add(time.Minute))); err != nil {
		t.Fatalf("attestation issued before retirement must still verify: %v", err)
	}

	// Something signed after retirement must not.
	late := claim
	late.IssuedAt = issued.Add(2 * time.Hour)
	late.ExpiresAt = late.IssuedAt.Add(time.Hour)
	lateAtt, err := Sign(priv, KeyIDFor(pub), late)
	if err != nil {
		t.Fatal(err)
	}
	err = VerifyWithRing(lateAtt, ring, WithClock(late.IssuedAt))
	if !errors.Is(err, ErrKeyRetired) {
		t.Fatalf("got %v, want ErrKeyRetired — a retired key that still signs makes rotation ceremonial", err)
	}
}

func TestKeyRingNotBefore(t *testing.T) {
	priv, pub := keyFromSeed(4)
	start := time.Unix(1_755_100_000, 0).UTC()

	ring := NewKeyRing()
	if err := ring.Add(KeyEntry{KeyID: "k", Alg: AlgEd25519, Public: pub, NotBefore: start}); err != nil {
		t.Fatal(err)
	}
	claim := sampleClaim()
	claim.IssuedAt = start.Add(-time.Hour)
	claim.ExpiresAt = start.Add(time.Hour)
	att, err := Sign(priv, "k", claim)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyWithRing(att, ring, WithClock(start)); !errors.Is(err, ErrKeyRetired) {
		t.Fatalf("got %v, want ErrKeyRetired for a key not yet active", err)
	}
}

func TestKeyRingValidation(t *testing.T) {
	ring := NewKeyRing()
	if err := ring.Add(KeyEntry{}); !errors.Is(err, ErrMalformed) {
		t.Fatalf("empty key id: got %v, want ErrMalformed", err)
	}
	if err := ring.Add(KeyEntry{KeyID: "k", Alg: "nope"}); !errors.Is(err, ErrUnknownAlg) {
		t.Fatalf("unknown alg: got %v, want ErrUnknownAlg", err)
	}
	now := time.Now()
	err := ring.Add(KeyEntry{KeyID: "k", NotBefore: now, NotAfter: now.Add(-time.Hour)})
	if !errors.Is(err, ErrMalformed) {
		t.Fatalf("retire-before-start: got %v, want ErrMalformed", err)
	}
	if err := ring.Retire("missing", now); !errors.Is(err, ErrUnknownKeyID) {
		t.Fatalf("got %v, want ErrUnknownKeyID", err)
	}
	if err := VerifyWithRing(nil, ring); !errors.Is(err, ErrMalformed) {
		t.Fatalf("nil attestation: got %v", err)
	}
	priv, pub := keyFromSeed(5)
	att, _ := Sign(priv, KeyIDFor(pub), sampleClaim())
	if err := VerifyWithRing(att, nil); !errors.Is(err, ErrMalformed) {
		t.Fatalf("nil ring: got %v", err)
	}
}

func TestKeyRingAlgMismatch(t *testing.T) {
	priv, pub := keyFromSeed(6)
	ring := NewKeyRing()
	if err := ring.AddEd25519(pub); err != nil {
		t.Fatal(err)
	}
	att, err := Sign(priv, KeyIDFor(pub), sampleClaim())
	if err != nil {
		t.Fatal(err)
	}
	att.Alg = "secp256k1"
	if err := VerifyWithRing(att, ring, WithClock(att.Claim.IssuedAt)); !errors.Is(err, ErrUnknownAlg) {
		t.Fatalf("got %v, want ErrUnknownAlg", err)
	}
}

func TestConcurrentKeyRingUse(t *testing.T) {
	ring := NewKeyRing()
	priv, pub := keyFromSeed(7)
	if err := ring.AddEd25519(pub); err != nil {
		t.Fatal(err)
	}
	att, err := Sign(priv, KeyIDFor(pub), sampleClaim())
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func(i int) {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 50; j++ {
				_ = VerifyWithRing(att, ring, WithClock(att.Claim.IssuedAt))
				_ = ring.KeyIDs()
				_, otherPub := keyFromSeed(byte(100 + i))
				_ = ring.AddEd25519(otherPub)
			}
		}(i)
	}
	for i := 0; i < 8; i++ {
		<-done
	}
}
