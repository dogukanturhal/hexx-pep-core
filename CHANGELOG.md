# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before
v1.0.0, any minor release may contain breaking changes.

## [Unreleased]

### Added

- `pkg/cryptoprofile`: crypto-agility seam. `SECURITY_PROFILE` resolves to a
  signature scheme and TLS key-exchange groups. The `enterprise` profile uses
  Ed25519 and X25519MLKEM768; the `cnsa2` profile selects SecP384r1MLKEM1024 for
  TLS, but its ML-DSA-87 signing path returns `ErrProfileUnavailable` until a
  validated implementation can be bound.
- `pkg/govdecision`: signed, time-boxed authorization decisions with a
  revocation epoch, a cached evaluator and Ed25519 signing.
- `pkg/spool`: file-backed, crash-safe store-and-forward queue with bounded
  retention and ordered reconcile.
- `pkg/resilient`: per-attempt timeout, three-state circuit breaker, backoff with
  jitter and an injectable clock.
- Public repository scaffolding: README, CI (vet, race tests, golangci-lint,
  govulncheck, CodeQL, OpenSSF Scorecard), Dependabot, tag-based releases,
  CONTRIBUTING (DCO), SECURITY, CODE_OF_CONDUCT and issue templates.

### Changed

- Internal planning identifiers and product names were removed from comments.
- Documentation states which parts are seams or unfinished (see the README
  section "Status and limitations").

## [0.1.0]

Earlier history is not tracked in this file.
