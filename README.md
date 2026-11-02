# hexx-pep-core

**Small Go building blocks for policy enforcement points: tamper-evident audit logs, signed offline decisions and a durable spool.**

[![CI](https://github.com/dogukanturhal/hexx-pep-core/actions/workflows/ci.yml/badge.svg)](https://github.com/dogukanturhal/hexx-pep-core/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/dogukanturhal/hexx-pep-core.svg)](https://pkg.go.dev/github.com/dogukanturhal/hexx-pep-core)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/dogukanturhal/hexx-pep-core/badge)](https://scorecard.dev/viewer/?uri=github.com/dogukanturhal/hexx-pep-core)

Status: tagged `v1.2.0`, standard library only, not independently audited, no FIPS validation of its own (see [Crypto and FIPS](#crypto-and-fips)).

[Quickstart](#quickstart) · [Docs](https://pkg.go.dev/github.com/dogukanturhal/hexx-pep-core) · [Architecture](#architecture) · [Security](#security) · [Contributing](#contributing)

## Hash-chain write and tamper detection

```go
var buf bytes.Buffer
sink := chain.NewJSONLChain(&buf)
for _, a := range []string{"open", "read", "close"} {
	_ = sink.Emit(context.Background(), &Event{Action: a})
}
fmt.Print(buf.String())
fmt.Println("intact:", verify(buf.String()) == nil)
bad := strings.Replace(buf.String(), `"read"`, `"drop"`, 1)
fmt.Println("tampered:", verify(bad))
```

Output:

```
{"seq":0,"action":"open"}
{"seq":1,"prev_hash":"6d544c41e1a74c8557f321b9ec34a3dfe4fc8e2f897bbffe13ef7ea365796cf2","action":"read"}
{"seq":2,"prev_hash":"81f9efd75276612004a4a71cfa582e58272730757917def652fdf56fdc0f8155","action":"close"}
intact: true
tampered: chain broken at seq 2
```

Editing line 1 changes its SHA-256, so line 2's `prev_hash` no longer matches. The
package writes the chain but does not ship a verifier, so `verify` below is yours
to write; it is about ten lines. The full program, which compiles and runs against
this module:

<details>
<summary>Complete example (main.go)</summary>

```go
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/dogukanturhal/hexx-pep-core/pkg/chain"
)

// Each product defines its own event and embeds chain.Stamp (seq + prev_hash).
type Event struct {
	chain.Stamp
	Action string `json:"action"`
}

// verify re-hashes each line and compares it with the next line's prev_hash.
func verify(log string) error {
	prev := ""
	for i, ln := range strings.Split(strings.TrimSuffix(log, "\n"), "\n") {
		var e Event
		if err := json.Unmarshal([]byte(ln), &e); err != nil || e.PrevHash != prev {
			return fmt.Errorf("chain broken at seq %d", i)
		}
		sum := sha256.Sum256([]byte(ln + "\n"))
		prev = hex.EncodeToString(sum[:])
	}
	return nil
}

func main() {
	// ... the ten lines shown above ...
}
```

</details>

## Why it exists

A policy enforcement point (PEP) sits in front of something sensitive, decides
whether a request may pass, and logs what it did. In disconnected, degraded or
limited-bandwidth conditions (DDIL) it may be unable to reach its policy decision
point or its log shipper, and it still has to decide, record and recover. This
module holds the pieces two such programs had in common:
[Talon](https://github.com/dogukanturhal/talon) (an HTTP identity-aware proxy) and
[Jess](https://github.com/dogukanturhal/jess) (an L4 broker for SSH, PostgreSQL and
RDP). They share an identity provider
([falcon-id](https://github.com/dogukanturhal/falcon-id)) and an audit shipper but
not their event shapes or policy engines, so this module is what they have in
common and nothing more.

## Quickstart

Requires Go 1.26 or newer (`cryptoprofile` uses `tls.SecP384r1MLKEM1024`).

```sh
go get github.com/dogukanturhal/hexx-pep-core@v1.2.0
```

Then use the example above, or run the checks on a clone:

```sh
go vet ./...
go test -race ./...
```

Choosing a signing scheme and a TLS posture from one environment variable:

```go
prof, err := cryptoprofile.Resolve(os.Getenv("SECURITY_PROFILE")) // "" means enterprise
signer, err := cryptoprofile.Signer(prof, issuerPrivateKey)       // govdecision.Signer
signed, err := govdecision.Sign(signer, decision)

// Hybrid post-quantum key exchange with a classical group alongside.
srv := &http.Server{TLSConfig: cryptoprofile.TLSConfig(prof)} // plus Certificates
```

With the default `enterprise` profile this signs with Ed25519 and offers
X25519MLKEM768. With `cnsa2`, `cryptoprofile.Signer` returns an error (see below),
while `TLSConfig` offers SecP384r1MLKEM1024.

## Architecture

Package map, with a test file for each package as evidence of the behaviour
described:

| Package | What it does | Tests |
|---|---|---|
| `pkg/chain` | `JSONLChain` writes newline-delimited JSON events. Each event carries `seq` and `prev_hash`, the SHA-256 of the exact previous line including its newline. Safe for concurrent use. | [chain_test.go](https://github.com/dogukanturhal/hexx-pep-core/blob/main/pkg/chain/chain_test.go) |
| `pkg/identity` | The `Identity` struct (`Subject`, `Email`, `Roles`, `Groups`, `Region`, `AMR`) with role, group and auth-method helpers, and a `Verifier` interface. | [identity_test.go](https://github.com/dogukanturhal/hexx-pep-core/blob/main/pkg/identity/identity_test.go) |
| `pkg/govdecision` | Signed, time-boxed authorization decisions per tier, with a revocation epoch per subject. `CachedEvaluator` serves a cached decision offline until its budget runs out, then denies. Pluggable `Signer`/`Verifier`; Ed25519 is implemented. | [evaluator_test.go](https://github.com/dogukanturhal/hexx-pep-core/blob/main/pkg/govdecision/evaluator_test.go), [decision_test.go](https://github.com/dogukanturhal/hexx-pep-core/blob/main/pkg/govdecision/decision_test.go) |
| `pkg/spool` | `FileSpool`: one fsynced, atomically renamed file per record, hash-chained, with ordered and retryable `Reconcile` into a sink. Retention is bounded by age, bytes or count; on overflow it returns `ErrSpoolFull` or drops the oldest record and reports every drop to a `DropLogger`. | [filespool_test.go](https://github.com/dogukanturhal/hexx-pep-core/blob/main/pkg/spool/filespool_test.go) |
| `pkg/resilient` | `Do` with per-attempt timeout, backoff with jitter and a retryable-error predicate; a three-state `Breaker`; a `Clock` interface with a fake for tests and skew-leeway helpers. | [resilient_test.go](https://github.com/dogukanturhal/hexx-pep-core/blob/main/pkg/resilient/resilient_test.go), [breaker_test.go](https://github.com/dogukanturhal/hexx-pep-core/blob/main/pkg/resilient/breaker_test.go) |
| `pkg/cryptoprofile` | Resolves `SECURITY_PROFILE` (`enterprise`, `cnsa2`) to a signature scheme and TLS key-exchange groups. The `cnsa2` signature half is not available yet. | [cryptoprofile_test.go](https://github.com/dogukanturhal/hexx-pep-core/blob/main/pkg/cryptoprofile/cryptoprofile_test.go), [tls_test.go](https://github.com/dogukanturhal/hexx-pep-core/blob/main/pkg/cryptoprofile/tls_test.go) |

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

## Crypto and FIPS

- **Implemented:** Ed25519 signing for decisions, and hybrid post-quantum TLS key
  exchange (X25519MLKEM768 for `enterprise`, SecP384r1MLKEM1024 for `cnsa2`), via
  the Go standard library. See [`signer.go`](https://github.com/dogukanturhal/hexx-pep-core/blob/main/pkg/cryptoprofile/signer.go)
  and [`tls.go`](https://github.com/dogukanturhal/hexx-pep-core/blob/main/pkg/cryptoprofile/tls.go).
- **Not implemented: ML-DSA signing.** The `cnsa2` profile names ML-DSA-87
  (FIPS 204), but `Signer`, `Verifier` and `Generate` return an error wrapping
  `ErrProfileUnavailable`. The Go standard library does not export ML-DSA in Go
  1.26 and this module binds no third-party one. The code is a fail-closed seam
  that never produces a signature; see [`mldsa.go`](https://github.com/dogukanturhal/hexx-pep-core/blob/main/pkg/cryptoprofile/mldsa.go).
  "ML-DSA-ready" means that seam, not a working signer.
- **FIPS 140-3:** this module has no validation. `cryptoprofile.FIPSApproved`
  reports whether the algorithms a profile selects are FIPS-approved, and
  `FIPSMode` reports whether the process runs Go's FIPS mode. Neither turns it on:
  that is a build and run setting (`GOFIPS140=v1.0.0 go build ./...` and
  `GODEBUG=fips140=on`). Using approved algorithms is not the same as being
  validated or compliant; see [`cryptoprofile.go`](https://github.com/dogukanturhal/hexx-pep-core/blob/main/pkg/cryptoprofile/cryptoprofile.go).

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

## Status and limitations

Read this before depending on it. No independent security review has been done.
Do not read the references to NIST controls or FIPS in the code comments as a
compliance claim.

- **`chain` has no verifier.** Checking a log means re-hashing the lines
  yourself, as the example above and `TestHashChainAdvancesAndTamperBreaks` do.
  There is no checkpointing, signing of the head, or external anchoring, so
  someone who can rewrite the whole file can rebuild a consistent chain.
- **Chain state is in memory.** `JSONLChain` starts at `seq` 0 with an empty
  `prev_hash` every time the process starts. A restart begins a new chain; nothing
  links it to the previous one.
- **There is no trusted time source.** The `resilient.Clock` interface and the
  skew-leeway helpers are the place an RFC 3161 time-stamp client could be
  plugged in, but none is included. Time in `govdecision` and `chain` comes from
  the local clock.
- **`identity` defines an interface only.** There is no OIDC or JWT verifier in
  this module; each program supplies its own `Verifier`.
- **`govdecision` ships Ed25519 only**, and the in-memory cache and epoch store
  do not survive a restart.
- **`spool` is file-based only.** A database-backed spool is mentioned in the
  package comments but not implemented here.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Commits need a DCO sign-off. Questions and
bug reports go to [Issues](https://github.com/dogukanturhal/hexx-pep-core/issues).
Everyone taking part is expected to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Security

Report vulnerabilities privately through
[GitHub private vulnerability reporting](https://github.com/dogukanturhal/hexx-pep-core/security/advisories/new)
or by email to dogukanturhal@hexxlock.com, as described in
[SECURITY.md](SECURITY.md). Do not open public issues for them.

## License

Apache License 2.0. See [LICENSE](LICENSE).
