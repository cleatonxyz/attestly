// Command attestly signs, verifies and inspects attestations from the shell.
//
//	attestly sign -seed <hex> -subject <s> [-set k=v ...]
//	attestly verify -key <hex> [-at <rfc3339>] [-expect-subject <s>] [file]
//	attestly digest [-canonical] [file]
//	attestly keygen
//
// Input is read from a file argument or stdin. Exit status is 0 when the
// attestation verifies, 1 when it does not, and 2 for usage errors — so it
// drops into a pipeline or a CI step without parsing the output.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/cleatonxyz/attestly"
)

const (
	exitOK    = 0
	exitFail  = 1
	exitUsage = 2
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(exitUsage)
	}
	switch os.Args[1] {
	case "verify":
		os.Exit(cmdVerify(os.Args[2:]))
	case "sign":
		os.Exit(cmdSign(os.Args[2:]))
	case "digest":
		os.Exit(cmdDigest(os.Args[2:]))
	case "keygen":
		os.Exit(cmdKeygen(os.Args[2:]))
	case "-h", "--help", "help":
		usage()
		os.Exit(exitOK)
	default:
		fmt.Fprintf(os.Stderr, "attestly: unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(exitUsage)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `attestly — sign and verify off-chain claims

  attestly sign -seed <hex> -subject <s> [-schema <s>] [-ttl <dur>] [-set k=v ...]
  attestly verify -key <hex> [-at <rfc3339>] [-expect-subject <s>] [-allow-expired] [file]
  attestly digest [-canonical] [file]
  attestly keygen

Reads the attestation from [file] or stdin.
Exit: 0 verified, 1 rejected, 2 usage error.
`)
}

func cmdVerify(args []string) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	keyHex := fs.String("key", "", "ed25519 public key, hex encoded (required)")
	at := fs.String("at", "", "verify as of this RFC3339 time instead of now")
	allowExpired := fs.Bool("allow-expired", false, "check the signature but not the time bounds")
	skew := fs.Duration("skew", 0, "tolerated clock drift, e.g. 30s")
	expectSubject := fs.String("expect-subject", "", "reject an attestation about a different subject")
	expectSchema := fs.String("expect-schema", "", "reject an attestation with a different schema")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *keyHex == "" {
		fmt.Fprintln(os.Stderr, "attestly: -key is required")
		return exitUsage
	}
	pubBytes, err := hex.DecodeString(*keyHex)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		fmt.Fprintf(os.Stderr, "attestly: -key must be %d hex-encoded bytes\n", ed25519.PublicKeySize)
		return exitUsage
	}

	att, err := readAttestation(fs.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, "attestly:", err)
		return exitUsage
	}

	opts := []attestly.VerifyOption{attestly.WithSkew(*skew)}
	if *expectSubject != "" {
		opts = append(opts, attestly.ExpectSubject(*expectSubject))
	}
	if *expectSchema != "" {
		opts = append(opts, attestly.ExpectSchema(*expectSchema))
	}
	if *allowExpired {
		opts = append(opts, attestly.AllowExpired())
	}
	if *at != "" {
		t, err := time.Parse(time.RFC3339, *at)
		if err != nil {
			fmt.Fprintln(os.Stderr, "attestly: -at must be RFC3339:", err)
			return exitUsage
		}
		opts = append(opts, attestly.WithClock(t))
	}

	if err := attestly.Verify(att, pubBytes, opts...); err != nil {
		// Name the failure mode: expired and forged call for different responses.
		switch {
		case errors.Is(err, attestly.ErrExpired):
			fmt.Fprintln(os.Stderr, "REJECTED expired:", err)
		case errors.Is(err, attestly.ErrBadSignature):
			fmt.Fprintln(os.Stderr, "REJECTED signature:", err)
		default:
			fmt.Fprintln(os.Stderr, "REJECTED:", err)
		}
		return exitFail
	}
	fmt.Printf("OK subject=%s schema=%s expires=%s\n",
		att.Claim.Subject, att.Claim.Schema, att.Claim.ExpiresAt.UTC().Format(time.RFC3339))
	return exitOK
}

// kvFlag collects repeated -set key=value pairs into a payload.
type kvFlag map[string]any

func (k kvFlag) String() string { return fmt.Sprintf("%v", map[string]any(k)) }

func (k kvFlag) Set(s string) error {
	i := strings.IndexByte(s, '=')
	if i <= 0 {
		return fmt.Errorf("want key=value, got %q", s)
	}
	key, val := s[:i], s[i+1:]
	// Integers become integers; everything else stays a string. Floats are
	// deliberately not parsed — the canonical encoding rejects them, and a
	// decimal that silently became a float would fail at signing time with a
	// confusing error instead of here.
	if n, err := strconv.ParseInt(val, 10, 64); err == nil {
		k[key] = n
	} else {
		k[key] = val
	}
	return nil
}

func cmdSign(args []string) int {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	seedHex := fs.String("seed", "", "ed25519 private key seed, hex encoded (required)")
	subject := fs.String("subject", "", "what the claim is about (required)")
	schema := fs.String("schema", "", "payload schema identifier")
	ttl := fs.Duration("ttl", 24*time.Hour, "how long the attestation stays valid")
	issuedAt := fs.String("at", "", "issue time as RFC3339, defaults to now")
	nonce := fs.String("nonce", "", "optional nonce")
	payload := kvFlag{}
	fs.Var(payload, "set", "payload entry key=value, repeatable")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *seedHex == "" || *subject == "" {
		fmt.Fprintln(os.Stderr, "attestly: -seed and -subject are required")
		return exitUsage
	}
	seed, err := hex.DecodeString(*seedHex)
	if err != nil || len(seed) != ed25519.SeedSize {
		fmt.Fprintf(os.Stderr, "attestly: -seed must be %d hex-encoded bytes\n", ed25519.SeedSize)
		return exitUsage
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	issued := time.Now().UTC()
	if *issuedAt != "" {
		issued, err = time.Parse(time.RFC3339, *issuedAt)
		if err != nil {
			fmt.Fprintln(os.Stderr, "attestly: -at must be RFC3339:", err)
			return exitUsage
		}
	}

	claim := attestly.Claim{
		Subject:   *subject,
		Schema:    *schema,
		IssuedAt:  issued,
		ExpiresAt: issued.Add(*ttl),
		Nonce:     *nonce,
	}
	if len(payload) > 0 {
		claim.Payload = payload
	}

	att, err := attestly.Sign(priv, attestly.KeyIDFor(pub), claim)
	if err != nil {
		fmt.Fprintln(os.Stderr, "attestly:", err)
		return exitFail
	}
	// Public key to stderr so `> att.json` captures only the attestation.
	fmt.Fprintf(os.Stderr, "public %s\nkey_id %s\n", hex.EncodeToString(pub), attestly.KeyIDFor(pub))
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(att); err != nil {
		fmt.Fprintln(os.Stderr, "attestly:", err)
		return exitFail
	}
	return exitOK
}

func cmdDigest(args []string) int {
	fs := flag.NewFlagSet("digest", flag.ContinueOnError)
	showCanonical := fs.Bool("canonical", false, "print the canonical bytes instead of the digest")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	att, err := readAttestation(fs.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, "attestly:", err)
		return exitUsage
	}
	if *showCanonical {
		b, err := att.Claim.Canonical()
		if err != nil {
			fmt.Fprintln(os.Stderr, "attestly:", err)
			return exitFail
		}
		os.Stdout.Write(b)
		fmt.Println()
		return exitOK
	}
	d, err := att.Claim.Digest()
	if err != nil {
		fmt.Fprintln(os.Stderr, "attestly:", err)
		return exitFail
	}
	fmt.Println(hex.EncodeToString(d[:]))
	return exitOK
}

func cmdKeygen(args []string) int {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintln(os.Stderr, "attestly:", err)
		return exitFail
	}
	// Private key to stdout, everything else to stderr, so `> key.hex` captures
	// only the secret and a stray terminal scroll does not.
	fmt.Fprintf(os.Stderr, "public  %s\nkey_id  %s\n", hex.EncodeToString(pub), attestly.KeyIDFor(pub))
	fmt.Println(hex.EncodeToString(priv.Seed()))
	return exitOK
}

func readAttestation(path string) (*attestly.Attestation, error) {
	var (
		b   []byte
		err error
	)
	if path == "" || path == "-" {
		b, err = io.ReadAll(os.Stdin)
	} else {
		b, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, fmt.Errorf("read input: %w", err)
	}
	var att attestly.Attestation
	if err := json.Unmarshal(b, &att); err != nil {
		return nil, fmt.Errorf("parse attestation: %w", err)
	}
	return &att, nil
}
