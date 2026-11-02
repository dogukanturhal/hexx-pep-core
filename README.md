# hexx-pep-core

[![CI](https://github.com/dogukanturhal/hexx-pep-core/actions/workflows/ci.yml/badge.svg)](https://github.com/dogukanturhal/hexx-pep-core/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/dogukanturhal/hexx-pep-core.svg)](https://pkg.go.dev/github.com/dogukanturhal/hexx-pep-core)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![OpenSSF Scorecard](https://api.securityscorecard.dev/projects/github.com/dogukanturhal/hexx-pep-core/badge)](https://securityscorecard.dev/viewer/?uri=github.com/dogukanturhal/hexx-pep-core)

Small Go building blocks for policy enforcement points: an audit hash chain, a
verified-identity type, signed offline authorization decisions, a durable
store-and-forward spool, a resilience kit and a crypto-profile switch.

## Who it's for

People writing a proxy or broker that sits in front of something sensitive and
has to decide, log and keep working when its control plane is unreachable. The
code was written for two such programs,
[Talon](https://github.com/dogukanturhal/talon) (an HTTP identity-aware proxy)
and [Jess](https://github.com/dogukanturhal/jess) (an L4 broker for SSH,
PostgreSQL and RDP), which share an identity provider
([falcon-id](https://github.com/dogukanturhal/falcon-id)) and an audit shipper
but not their event shapes or policy engines. This module is what they have in
common and nothing more. Go 1.26 or newer.

## Features

Everything below exists in `pkg/` and has tests. The standard library is the only
dependency.

| Package | What it does |
|---|---|
| `pkg/chain` | `JSONLChain` writes newline-delimited JSON events. Each event carries `seq` and `prev_hash`, where `prev_hash` is the SHA-256 of the exact previous line including its newline. Safe for concurrent use. |
| `pkg/identity` | The `Identity` struct (`Subject`, `Email`, `Roles`, `Groups`, `Region`, `AMR`) with role, group and auth-method helpers, and a `Verifier` interface. |
| `pkg/govdecision` | Signed, time-boxed authorization decisions per tier, with a revocation epoch per subject. `CachedEvaluator` serves a cached decision offline until its budget runs out, then denies. Pluggable `Signer`/`Verifier`; Ed25519 is implemented. |
| `pkg/spool` | `FileSpool`: one fsynced, atomically renamed file per record, hash-chained, with ordered and retryable `Reconcile` into a sink. Retention is bounded by age, bytes or count; on overflow it either returns `ErrSpoolFull` or drops the oldest record and reports every drop to a `DropLogger`. |
| `pkg/resilient` | `Do` with per-attempt timeout, backoff with jitter and a retryable-error predicate; a three-state `Breaker`; a `Clock` interface with a fake for tests and skew-leeway helpers. |
| `pkg/cryptoprofile` | Resolves `SECURITY_PROFILE` (`enterprise`, `cnsa2`) to a signature scheme and TLS key-exchange groups. See the limitations: the `cnsa2` signature half is not working yet. |

## Quickstart

```sh
go get github.com/dogukanturhal/hexx-pep-core@main
```

No version is tagged yet, so `@main` is what works today. A hash-chained audit
log in a dozen lines:

```go
package main

import (
	"context"
	"os"
	"time"

	"github.com/dogukanturhal/hexx-pep-core/pkg/chain"
)

type Event struct {
	chain.Stamp                    // seq + prev_hash, filled in by the sink
	Time        time.Time `json:"time"`
	Subject     string    `json:"subject,omitempty"`
	Action      string    `json:"action"`
}

// Optional: lets the sink fill Time for you.
func (e *Event) StampTime(t time.Time) {
	if e.Time.IsZero() {
		e.Time = t
	}
}

func main() {
	sink := chain.NewJSONLChain(os.Stdout)
	_ = sink.Emit(context.Background(), &Event{Action: "open", Subject: "alice"})
	_ = sink.Emit(context.Background(), &Event{Action: "close", Subject: "alice"})
}
```

Each product keeps its own event struct and embeds `chain.Stamp`. `seq` and
`prev_hash` appear at the start of each line.

Choosing a signing scheme and a TLS posture from one environment variable:

```go
import (
	"net/http"
	"os"

	"github.com/dogukanturhal/hexx-pep-core/pkg/cryptoprofile"
	"github.com/dogukanturhal/hexx-pep-core/pkg/govdecision"
)

prof, err := cryptoprofile.Resolve(os.Getenv("SECURITY_PROFILE")) // "" means enterprise
signer, err := cryptoprofile.Signer(prof, issuerPrivateKey)       // govdecision.Signer
signed, err := govdecision.Sign(signer, decision)

// Hybrid post-quantum key exchange with a classical group alongside.
srv := &http.Server{TLSConfig: cryptoprofile.TLSConfig(prof)} // plus Certificates
```

With the default `enterprise` profile this signs with Ed25519 and offers
X25519MLKEM768. With `cnsa2`, `cryptoprofile.Signer` returns an error (see
below), while `TLSConfig` offers SecP384r1MLKEM1024.

FIPS 140-3 mode is not selected by this package. It is a build and run setting
(`GOFIPS140=v1.0.0 go build ./...` and `GODEBUG=fips140=on`).
`cryptoprofile.FIPSMode` only reports whether it is on.

Run the tests:

```sh
go vet ./...
go test -race ./...
```

## How it compares

- **Using the standard library directly.** Most of this is thin. The reason to
  use it is that two programs already agree on the chain format, the decision
  wire format and the spool record format; if you only need one of those, copying
  the file is reasonable.
- **Transparency logs and ledgers** (Trillian, Sigstore Rekor) give you
  third-party verifiable, append-only storage with inclusion proofs. `chain` is
  one process hashing its own output: it makes tampering with a log file
  detectable by someone who holds the log and trusts the first line, nothing
  more.
- **Retry and breaker libraries** (`cenkalti/backoff`, `sony/gobreaker`,
  `avast/retry-go`) are more widely used than `resilient`. Use them if you do not
  need the injectable clock or the skew helpers that `govdecision` shares.
- **OPA and Cedar** decide policy. `govdecision` does not: it carries and caches
  signed results of a decision made elsewhere, so a proxy can keep honouring them
  while disconnected.

## Architecture

```
  token --> identity.Verifier --> identity.Identity
                                        |
                                        v
  PDP (Rego, SpiceDB, ...) --> govdecision.Evaluator --signed Decision--> cached,
                                        |                  honoured offline until
                                        v                  the tier budget expires
                               enforce + audit event
                                        |
                       chain.JSONLChain (seq, prev_hash)
                                        |
                       stdout / shipper    or    spool.FileSpool --Reconcile--> sink

  cryptoprofile: picks the Signer/Verifier given to govdecision and the TLS groups
  resilient:     wraps calls to the PDP, shipper and sink (timeout, backoff, breaker)
```

## Status and limitations

This is early code. Read this before depending on it.

- **Post-quantum signing is a seam, not a feature.** In the `cnsa2` profile,
  `cryptoprofile.Signer`, `Verifier` and `Generate` return an error wrapping
  `ErrProfileUnavailable`. ML-DSA-87 needs a validated implementation, and the Go
  standard library does not export one yet (the public `crypto/mldsa` API is
  proposed for Go 1.27). It fails closed: it never produces a fake signature. The
  post-quantum part that does work is the hybrid TLS key exchange.
- **`chain` has no verifier.** The package writes the chain; it does not read one
  back. Checking a log means re-hashing the lines yourself, as the test
  `TestHashChainAdvancesAndTamperBreaks` does. There is no checkpointing, signing
  of the head, or external anchoring, so someone who can rewrite the whole file
  can rebuild a consistent chain.
- **Chain state is in memory.** `JSONLChain` starts at `seq` 0 with an empty
  `prev_hash` every time the process starts. A restart begins a new chain; nothing
  links it to the previous one.
- **There is no trusted time source.** The `resilient.Clock` interface and the
  skew-leeway helpers are the place an RFC 3161 time-stamp client could be
  plugged in, but no such client is included or wired. Time in `govdecision` and
  `chain` comes from the local clock.
- **`identity` defines an interface only.** There is no OIDC or JWT verifier in
  this module; each program supplies its own `Verifier`.
- **`govdecision` ships Ed25519 only**, and the in-memory cache and epoch store
  do not survive a restart.
- **`spool` is file-based only.** A database-backed spool is mentioned in the
  package comments but not implemented here.
- Version 0.x: the API can change in any release.
- The module requires Go 1.26 because `cryptoprofile` uses
  `tls.SecP384r1MLKEM1024`.
- No independent security review has been done. Do not read the references to
  NIST controls or FIPS in the code comments as a compliance claim.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Commits need a DCO sign-off. Everyone
taking part is expected to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Security

Please report vulnerabilities privately, as described in
[SECURITY.md](SECURITY.md). Do not open public issues for them.

## License

Apache License 2.0. See [LICENSE](LICENSE).
