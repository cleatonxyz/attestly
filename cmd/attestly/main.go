// Command attestly verifies and inspects attestations from the shell.
//
//	attestly verify -key <hex> [-at <rfc3339>] [file]
//	attestly digest [file]
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
	fmt.Fprint(os.Stderr, `attestly — verify signed off-chain claims

  attestly verify -key <hex> [-at <rfc3339>] [-allow-expired] [file]
  attestly digest [file]
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
