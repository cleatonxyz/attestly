// Command basic signs a claim, prints it, and verifies it back.
//
//	go run ./examples/basic
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/cleatonxyz/attestly"
)

func main() {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	claim := attestly.Claim{
		Subject: "base:0x1f98431c8ad98523631ae4a59f267346ea31f984",
		Schema:  "cleaton.horizon/v1",
		Payload: map[string]any{
			"horizon_days": int64(9),
			"confidence":   "0.70", // decimals travel as strings: floats are rejected
		},
		IssuedAt:  time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(24 * time.Hour),
	}

	att, err := attestly.Sign(priv, attestly.KeyIDFor(pub), claim)
	if err != nil {
		log.Fatal(err)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(att); err != nil {
		log.Fatal(err)
	}

	if err := attestly.Verify(att, pub); err != nil {
		log.Fatal(err)
	}
	fmt.Println("\nverified now")

	// A day later the signature is still good but the claim is stale, and the
	// caller can tell the two apart.
	err = attestly.Verify(att, pub, attestly.WithClock(time.Now().Add(48*time.Hour)))
	fmt.Println("in 48h:", err, "| expired?", errors.Is(err, attestly.ErrExpired))
}
