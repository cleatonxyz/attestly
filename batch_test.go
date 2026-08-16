package attestly

import (
	"crypto/ed25519"
	"fmt"
	"testing"
	"time"
)

func TestVerifyBatchSeparatesFailureKinds(t *testing.T) {
	// The reason the summary is split by kind: 5% expired means a stale cache,
	// 5% forged means an attack. One "failed" count cannot tell them apart.
	priv, pub := keyFromSeed(11)
	ring := NewKeyRing()
	if err := ring.AddEd25519(pub); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_755_000_000, 0).UTC()

	mk := func(subject string, issued, expires time.Time) *Attestation {
		c := Claim{Subject: subject, Schema: "s", IssuedAt: issued, ExpiresAt: expires}
		att, err := Sign(priv, KeyIDFor(pub), c)
		if err != nil {
			t.Fatal(err)
		}
		return att
	}

	good := mk("a", now.Add(-time.Hour), now.Add(time.Hour))
	expired := mk("b", now.Add(-48*time.Hour), now.Add(-24*time.Hour))
	forged := mk("c", now.Add(-time.Hour), now.Add(time.Hour))
	forged.Sig[0] ^= 0xff
	unknownKey := mk("d", now.Add(-time.Hour), now.Add(time.Hour))
	unknownKey.KeyID = "not-in-ring"

	atts := []*Attestation{good, expired, forged, unknownKey}
	results, summary := VerifyBatch(atts, ring, WithClock(now))

	if summary.Total != 4 || summary.Verified != 1 || summary.Expired != 1 ||
		summary.BadSig != 1 || summary.UnknownKey != 1 {
		t.Fatalf("summary = %+v", summary)
	}
	if summary.AllVerified() {
		t.Fatal("AllVerified must be false")
	}
	// Results keep input order even though workers finish in any order.
	for i, r := range results {
		if r.Index != i {
			t.Fatalf("result %d has index %d", i, r.Index)
		}
	}
	if !results[0].OK() || results[1].OK() {
		t.Fatal("result order does not match input")
	}
	if got := len(Failures(results)); got != 3 {
		t.Fatalf("Failures returned %d, want 3", got)
	}
}

func TestVerifyBatchAllGood(t *testing.T) {
	priv, pub := keyFromSeed(12)
	ring := NewKeyRing()
	if err := ring.AddEd25519(pub); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_755_000_000, 0).UTC()

	atts := make([]*Attestation, 200)
	for i := range atts {
		c := Claim{
			Subject:   fmt.Sprintf("pool-%d", i),
			Schema:    "s",
			Payload:   map[string]any{"i": int64(i)},
			IssuedAt:  now.Add(-time.Hour),
			ExpiresAt: now.Add(time.Hour),
		}
		att, err := Sign(priv, KeyIDFor(pub), c)
		if err != nil {
			t.Fatal(err)
		}
		atts[i] = att
	}
	results, summary := VerifyBatch(atts, ring, WithClock(now))
	if !summary.AllVerified() {
		t.Fatalf("summary = %+v", summary)
	}
	if len(results) != 200 {
		t.Fatalf("got %d results", len(results))
	}
}

func TestVerifyBatchEmpty(t *testing.T) {
	results, summary := VerifyBatch(nil, NewKeyRing())
	if len(results) != 0 || summary.Total != 0 {
		t.Fatalf("results=%v summary=%+v", results, summary)
	}
	if summary.AllVerified() {
		t.Fatal("an empty batch is not 'all verified'")
	}
}

func TestExpectSubjectBlocksSubstitution(t *testing.T) {
	// A validly signed, unexpired attestation about a *different* subject is
	// exactly what substitution looks like, and the signature check alone will
	// happily accept it.
	priv, pub := keyFromSeed(13)
	c := sampleClaim()
	att, err := Sign(priv, KeyIDFor(pub), c)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(att, pub, WithClock(c.IssuedAt), ExpectSubject(c.Subject)); err != nil {
		t.Fatalf("matching subject: %v", err)
	}
	err = Verify(att, pub, WithClock(c.IssuedAt), ExpectSubject("base:0xsomeoneelse"))
	if err == nil {
		t.Fatal("a claim about another subject must be rejected")
	}
}

func TestExpectSchemaAndMaxTTL(t *testing.T) {
	priv, pub := keyFromSeed(14)
	c := sampleClaim()
	att, err := Sign(priv, KeyIDFor(pub), c)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(att, pub, WithClock(c.IssuedAt), ExpectSchema("cleaton.horizon/v1")); err != nil {
		t.Fatalf("matching schema: %v", err)
	}
	if err := Verify(att, pub, WithClock(c.IssuedAt), ExpectSchema("other/v1")); err == nil {
		t.Fatal("schema mismatch must be rejected")
	}
	// The sample claim spans 24h.
	if err := Verify(att, pub, WithClock(c.IssuedAt), MaxTTL(48*time.Hour)); err != nil {
		t.Fatalf("ttl within limit: %v", err)
	}
	if err := Verify(att, pub, WithClock(c.IssuedAt), MaxTTL(time.Hour)); err == nil {
		t.Fatal("an over-long validity window must be rejectable")
	}
}

func TestValidHelper(t *testing.T) {
	priv, pub := keyFromSeed(15)
	att, err := Sign(priv, KeyIDFor(pub), sampleClaim())
	if err != nil {
		t.Fatal(err)
	}
	if !Valid(att, pub, WithClock(att.Claim.IssuedAt)) {
		t.Fatal("should be valid")
	}
	if Valid(att, ed25519.PublicKey(make([]byte, ed25519.PublicKeySize)), WithClock(att.Claim.IssuedAt)) {
		t.Fatal("zero key must not validate")
	}
}

func TestClaimTTL(t *testing.T) {
	c := sampleClaim()
	if got := c.TTL(); got != 24*time.Hour {
		t.Fatalf("TTL = %v, want 24h", got)
	}
}

func BenchmarkVerifyBatch(b *testing.B) {
	priv, pub := keyFromSeed(16)
	ring := NewKeyRing()
	if err := ring.AddEd25519(pub); err != nil {
		b.Fatal(err)
	}
	now := time.Unix(1_755_000_000, 0).UTC()
	atts := make([]*Attestation, 100)
	for i := range atts {
		att, err := Sign(priv, KeyIDFor(pub), Claim{
			Subject: fmt.Sprintf("p-%d", i), Schema: "s",
			IssuedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour),
		})
		if err != nil {
			b.Fatal(err)
		}
		atts[i] = att
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, s := VerifyBatch(atts, ring, WithClock(now)); !s.AllVerified() {
			b.Fatal("batch failed")
		}
	}
}
