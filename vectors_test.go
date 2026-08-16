package attestly

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
	"time"
)

// vectorFile is the contract with implementations in other languages. A
// verifier written in TypeScript for the Cloudflare Worker is expected to load
// this same file and reproduce every digest and signature.
type vectorFile struct {
	Domain   string   `json:"domain"`
	Alg      string   `json:"alg"`
	SeedHex  string   `json:"seed_hex"`
	PubKey   string   `json:"public_key_hex"`
	Cases    []vector `json:"cases"`
	Comments string   `json:"_comment"`
}

type vector struct {
	Name         string `json:"name"`
	CanonicalStr string `json:"canonical"`
	DigestHex    string `json:"digest_hex"`
	SigB64       string `json:"sig_b64"`
}

func loadVectors(t *testing.T) vectorFile {
	t.Helper()
	b, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var v vectorFile
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	if len(v.Cases) == 0 {
		t.Fatal("vectors file has no cases")
	}
	return v
}

// TestVectors is the regression guard on the wire format. Anything that changes
// the canonical bytes, the domain string, or the digest breaks it.
func TestVectors(t *testing.T) {
	v := loadVectors(t)

	if v.Domain != Domain {
		t.Fatalf("domain drift: file %q, package %q", v.Domain, Domain)
	}
	seed, err := hex.DecodeString(v.SeedHex)
	if err != nil {
		t.Fatalf("bad seed hex: %v", err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	if hex.EncodeToString(pub) != v.PubKey {
		t.Fatalf("public key drift: %s vs %s", hex.EncodeToString(pub), v.PubKey)
	}

	for _, c := range v.Cases {
		t.Run(c.Name, func(t *testing.T) {
			claim := vectorClaim(t, c.Name)

			gotCanonical := mustCanonical(t, claim)
			if gotCanonical != c.CanonicalStr {
				t.Fatalf("canonical drift:\n got %s\nwant %s", gotCanonical, c.CanonicalStr)
			}

			d, err := claim.Digest()
			if err != nil {
				t.Fatalf("Digest: %v", err)
			}
			if hex.EncodeToString(d[:]) != c.DigestHex {
				t.Fatalf("digest drift:\n got %s\nwant %s", hex.EncodeToString(d[:]), c.DigestHex)
			}

			sig, err := base64.StdEncoding.DecodeString(c.SigB64)
			if err != nil {
				t.Fatalf("bad sig b64: %v", err)
			}
			att := &Attestation{Claim: claim, KeyID: KeyIDFor(pub), Alg: AlgEd25519, Sig: sig}
			if err := Verify(att, pub, WithClock(claim.IssuedAt)); err != nil {
				t.Fatalf("stored signature does not verify: %v", err)
			}
		})
	}
}

// vectorClaim maps a vector name to the claim it was generated from. Keeping
// the constructor in code rather than reading the claim back from JSON means
// the test also covers the Go types, not just the encoder.
func vectorClaim(t *testing.T, name string) Claim {
	t.Helper()
	switch name {
	case "horizon":
		return sampleClaim()
	case "minimal":
		return Claim{
			Subject:   "base:0xdead",
			Schema:    "cleaton.horizon/v1",
			IssuedAt:  time.Unix(1_755_000_000, 0).UTC(),
			ExpiresAt: time.Unix(1_755_003_600, 0).UTC(),
		}
	case "nested":
		return Claim{
			Subject: "arbitrum:0xbeef",
			Schema:  "cleaton.portfolio/v1",
			Payload: map[string]any{
				"positions": []any{
					map[string]any{"pool": "0xaaa", "horizon_days": int64(3)},
					map[string]any{"pool": "0xbbb", "horizon_days": int64(21)},
				},
				"unicode": "héllo\n\"quoted\"",
				"empty":   nil,
				"flag":    true,
			},
			IssuedAt:  time.Unix(1_755_000_000, 0).UTC(),
			ExpiresAt: time.Unix(1_755_086_400, 0).UTC(),
			Nonce:     "n-1",
		}
	default:
		t.Fatalf("unknown vector %q — add it to vectorClaim", name)
		return Claim{}
	}
}
