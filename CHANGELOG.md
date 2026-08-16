# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning is [SemVer](https://semver.org/); while on `v0` the public API may
change in a minor release.

## [Unreleased]

### Added

- `KeyRing` + `VerifyWithRing`: key rotation where retired keys keep verifying
  what they signed while active, but sign nothing new.
- `VerifyBatch` / `Summarize` / `Failures`: concurrent verification with a
  summary split by failure kind (expired vs forged vs unknown key).
- `Algorithm` + `RegisterAlgorithm`: pluggable signature algorithms, so
  secp256k1 can be added without this package taking the dependency.
- Verify options `ExpectSubject`, `ExpectSchema`, `MaxTTL`; helpers `Valid` and
  `Claim.TTL`.
- `attestly sign` CLI command, plus `-expect-subject` / `-expect-schema` on
  `verify`.

### Changed

- Canonical encoding moved to `internal/canonical` with its own tests and
  benchmark. The produced bytes are unchanged — the committed test vectors
  still pass.

## [0.1.0] - 2026-08-16

### Added

- Initial release.
