# attestly

Sign and verify short-lived off-chain claims, in Go, with no dependencies.

A claim says something about a subject until an expiry. Signing it produces an
attestation that anyone holding the public key can check without contacting the
issuer — and because the digest comes from a canonical encoding, an independent
implementation reproduces the same bytes.

> **Status: v0.** The API can still change. The wire format is pinned by
> committed test vectors, so digests will not move silently.

## Install

```bash
go get github.com/cleatonxyz/attestly
```

## Use

```go
claim := attestly.Claim{
    Subject: "base:0x1f98431c8ad98523631ae4a59f267346ea31f984",
    Schema:  "cleaton.horizon/v1",
    Payload: map[string]any{
        "horizon_days": int64(9),
        "confidence":   "0.70",
    },
    IssuedAt:  time.Now().UTC(),
    ExpiresAt: time.Now().UTC().Add(24 * time.Hour),
}

att, err := attestly.Sign(priv, attestly.KeyIDFor(pub), claim)
if err != nil {
    return err
}

err = attestly.Verify(att, pub)
switch {
case errors.Is(err, attestly.ErrExpired):     // stale, refetch
case errors.Is(err, attestly.ErrBadSignature): // forged, alert
case err != nil:                               // malformed
}
```

Runnable version: `go run ./examples/basic`.

## CLI

```bash
go install github.com/cleatonxyz/attestly/cmd/attestly@latest

attestly keygen > key.hex          # secret to stdout, public key to stderr
attestly verify -key <pubhex> a.json
attestly digest -canonical a.json  # exactly what gets hashed
```

Exit status is 0 verified, 1 rejected, 2 usage error — it drops straight into a
CI step.

## Three decisions worth knowing

**Floats are rejected.** A `float64` has no single agreed decimal form across
languages, so two correct implementations can hash different bytes. Pass
decimals as strings (`"0.70"`) or fixed-point integers. An ambiguous encoding
would defeat the point of the library, so this fails loudly instead.

**A bad signature is reported before an expiry.** Verification checks the
signature first. If it reported "expired" for a forgery, a caller could retry
with `AllowExpired()` and accept it.

**The digest is domain-separated.** Every hash covers `attestly/v1\n` first, so
a signature here can never be replayed as a signature over something else made
with the same key.

## Test vectors

`testdata/vectors.json` holds canonical bytes, digests, and signatures for a
fixed test key. It is the contract for ports: a verifier in another language
should load that file and reproduce every value. `go test` checks the Go
implementation against it on every run, so a change to the encoding cannot land
unnoticed.

Regenerate only when the format changes on purpose:

```bash
go run ./internal/genvectors > testdata/vectors.json
```

## Roadmap

- secp256k1 + EIP-712 signing, so attestations verify inside an EVM contract
- WASM build of the verifier, so a Cloudflare Worker checks the same bytes
- key rotation helpers (multi-key resolver keyed by `key_id`)

## License

MIT
