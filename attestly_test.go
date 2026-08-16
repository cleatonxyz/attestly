package attestly

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// Fixed seed so every run signs the same bytes. Obviously not a real key: it is
// 32 bytes of 0x01 and must never be used for anything.
var testSeed = strings.Repeat("\x01", ed25519.SeedSize)

func testKey(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	priv := ed25519.NewKeyFromSeed([]byte(testSeed))
	return priv, priv.Public().(ed25519.PublicKey)
}

func sampleClaim() Claim {
	return Claim{
		Subject: "base:0x1f98431c8ad98523631ae4a59f267346ea31f984",
		Schema:  "cleaton.horizon/v1",
		Payload: map[string]any{
			"horizon_days": int64(9),
			"confidence":   "0.70", // decimal as string on purpose
			"model":        "ensemble-a",
		},
		IssuedAt:  time.Unix(1_755_000_000, 0).UTC(),
		ExpiresAt: time.Unix(1_755_086_400, 0).UTC(),
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	priv, pub := testKey(t)
	c := sampleClaim()

	att, err := Sign(priv, KeyIDFor(pub), c)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := Verify(att, pub, WithClock(c.IssuedAt.Add(time.Hour))); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestCanonicalIsStableAcrossMapOrder(t *testing.T) {
	// Go randomizes map iteration; the canonical form must not inherit that.
	c1 := sampleClaim()
	c2 := sampleClaim()
	c2.Payload = map[string]any{
		"model":        "ensemble-a",
		"confidence":   "0.70",
		"horizon_days": int64(9),
	}
	b1, err := c1.Canonical()
	if err != nil {
		t.Fatalf("Canonical: %v", err)
	}
	for i := 0; i < 50; i++ {
		b2, err := c2.Canonical()
		if err != nil {
			t.Fatalf("Canonical: %v", err)
		}
		if string(b1) != string(b2) {
			t.Fatalf("canonical form not stable:\n%s\n%s", b1, b2)
		}
	}
}

func TestTamperedPayloadFailsSignature(t *testing.T) {
	priv, pub := testKey(t)
	att, err := Sign(priv, "k1", sampleClaim())
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	att.Claim.Payload["horizon_days"] = int64(30)

	err = Verify(att, pub, WithClock(att.Claim.IssuedAt))
	if !errors.Is(err, ErrBadSignature) {
		t.Fatalf("got %v, want ErrBadSignature", err)
	}
}

func TestTimeBounds(t *testing.T) {
	priv, pub := testKey(t)
	c := sampleClaim()
	att, err := Sign(priv, "k1", c)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	tests := []struct {
		name string
		opts []VerifyOption
		want error
	}{
		{"inside window", []VerifyOption{WithClock(c.IssuedAt.Add(time.Hour))}, nil},
		{"after expiry", []VerifyOption{WithClock(c.ExpiresAt.Add(time.Second))}, ErrExpired},
		{"before issue", []VerifyOption{WithClock(c.IssuedAt.Add(-time.Second))}, ErrNotYetValid},
		{"expiry within skew", []VerifyOption{WithClock(c.ExpiresAt.Add(30 * time.Second)), WithSkew(time.Minute)}, nil},
		{"expired but audited", []VerifyOption{WithClock(c.ExpiresAt.Add(time.Hour)), AllowExpired()}, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := Verify(att, pub, tc.opts...)
			if tc.want == nil && err != nil {
				t.Fatalf("got %v, want nil", err)
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestForgedSignatureIsReportedBeforeExpiry(t *testing.T) {
	// An expired forgery must report the forgery. Reporting "expired" would let
	// a caller retry with AllowExpired and accept a bad signature.
	priv, pub := testKey(t)
	att, err := Sign(priv, "k1", sampleClaim())
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	att.Sig[0] ^= 0xff

	err = Verify(att, pub, WithClock(att.Claim.ExpiresAt.Add(time.Hour)))
	if !errors.Is(err, ErrBadSignature) {
		t.Fatalf("got %v, want ErrBadSignature", err)
	}
}

func TestFloatPayloadRejected(t *testing.T) {
	c := sampleClaim()
	c.Payload["confidence"] = 0.7
	if _, err := c.Digest(); !errors.Is(err, ErrUnsupportedType) {
		t.Fatalf("got %v, want ErrUnsupportedType", err)
	}
}

func TestWrongKeyRejected(t *testing.T) {
	priv, _ := testKey(t)
	att, err := Sign(priv, "k1", sampleClaim())
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	otherPriv := ed25519.NewKeyFromSeed([]byte(strings.Repeat("\x02", ed25519.SeedSize)))
	err = Verify(att, otherPriv.Public().(ed25519.PublicKey), WithClock(att.Claim.IssuedAt))
	if !errors.Is(err, ErrBadSignature) {
		t.Fatalf("got %v, want ErrBadSignature", err)
	}
}

func TestUnknownAlgRejected(t *testing.T) {
	priv, pub := testKey(t)
	att, err := Sign(priv, "k1", sampleClaim())
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	att.Alg = "secp256k1"
	if err := Verify(att, pub, WithClock(att.Claim.IssuedAt)); !errors.Is(err, ErrUnknownAlg) {
		t.Fatalf("got %v, want ErrUnknownAlg", err)
	}
}

func TestMalformedClaims(t *testing.T) {
	tests := []struct {
		name  string
		claim Claim
	}{
		{"no subject", Claim{Schema: "s", IssuedAt: time.Unix(1, 0), ExpiresAt: time.Unix(2, 0)}},
		{"expiry before issue", Claim{Subject: "x", IssuedAt: time.Unix(9, 0), ExpiresAt: time.Unix(2, 0)}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.claim.Digest(); !errors.Is(err, ErrMalformed) {
				t.Fatalf("got %v, want ErrMalformed", err)
			}
		})
	}
}

func TestJSONRoundTripVerifies(t *testing.T) {
	priv, pub := testKey(t)
	att, err := Sign(priv, KeyIDFor(pub), sampleClaim())
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	b, err := json.Marshal(att)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var back Attestation
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	// Integers survive the trip through float64 and still verify.
	if err := Verify(&back, pub, WithClock(back.Claim.IssuedAt)); err != nil {
		t.Fatalf("Verify after round trip: %v", err)
	}
}

func TestDigestMatchesPublishedVector(t *testing.T) {
	// This value is committed in testdata/vectors.json. If a change moves it,
	// every attestation ever published stops verifying, so the test exists to
	// make that break impossible to do by accident.
	c := sampleClaim()
	d, err := c.Digest()
	if err != nil {
		t.Fatalf("Digest: %v", err)
	}
	got := hex.EncodeToString(d[:])
	vec := loadVectors(t)
	if got != vec.Cases[0].DigestHex {
		t.Fatalf("digest drift:\n got %s\nwant %s\ncanonical: %s", got, vec.Cases[0].DigestHex, mustCanonical(t, c))
	}
}

func mustCanonical(t *testing.T, c Claim) string {
	t.Helper()
	b, err := c.Canonical()
	if err != nil {
		t.Fatalf("Canonical: %v", err)
	}
	return string(b)
}
