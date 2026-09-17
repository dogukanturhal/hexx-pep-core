# hexx-pep-core

Shared primitives used by every HexxLock Policy Enforcement Point.

The two PEPs in production today —
[**Talon**](https://github.com/dogukanturhal/talon) (HTTP IAP for internal admin services) and
[**Jess**](https://github.com/dogukanturhal/jess) (L4 broker for SSH /
Postgres / RDP) — both derive their operator identity from the same
Falcon-ID OIDC tokens and both emit audit events to the same shipper.
They do NOT share their event shapes (HTTP-rich vs. broker-shaped) or
their policy layers (Rego + SpiceDB vs. role-intersection). Forcing one
struct would be Procrustean.

What they DO share — and what this module provides — is the integrity
primitive under both audit funnels and the shape of the verified identity:

| Package | Purpose |
|---|---|
| `pkg/chain` | Tamper-evident SHA-256 hash chain over newline-delimited JSON events. NIST SP 800-53 AU-9/AU-10 / SOC 2 CC7.2 evidence. Bit-for-bit identical to the original Jess implementation so traces remain replayable. |
| `pkg/identity` | The verified operator (`Subject`, `Email`, `Roles`, `Groups`, `Region`, `AMR`) + the `Verifier` interface. |
| `pkg/govdecision` | DDIL Phase-3: governed staleness-budget decisions. Signed, time-boxed, revocation-epoch-aware authorization results a PEP can honour **offline** within budget, then fail closed. Pluggable `Signer`/`Verifier` (Ed25519 now, ML-DSA later) — the `SECURITY_PROFILE` crypto-agility seam. |
| `pkg/spool` | DDIL Phase-3: durable, crash-safe store-and-forward. Append-only, fsync + atomic write-then-rename; ordered, idempotent `Reconcile` into a WORM sink; bounded retention (default 30 days) with backpressure or logged oldest-first drop — never silent truncation. |
| `pkg/resilient` | DDIL Phase-3: uniform resilience kit — per-attempt timeout + three-state circuit breaker + exponential backoff with full jitter, plus a `Clock` seam with skew-leeway helpers. Stdlib-only. |
| `pkg/cryptoprofile` | Crypto-agility seam (P2.6): resolves `SECURITY_PROFILE ∈ {enterprise, cnsa2}` into a concrete signature scheme + TLS key-exchange groups, so FIPS 140-3 / post-quantum / CNSA 2.0 posture is **config, not a code fork**. `Signer`/`Verifier` return `govdecision`-compatible implementations — enterprise = **Ed25519** (fully implemented); cnsa2 = **ML-DSA-87**, a documented fail-closed seam (`ErrProfileUnavailable`) until Go 1.27's `crypto/mldsa` lands. `TLSConfig`/`KEMGroups` set a hybrid PQC group with a classical group alongside (never PQC-only): enterprise **X25519MLKEM768**, cnsa2 **SecP384r1MLKEM1024** (ML-KEM-1024). FIPS 140-3 mode is a build/run flag (`GOFIPS140=v1.0.0`, CMVP #5247), not code. |

The rationale is recorded in an architecture decision record kept with the
platform's infrastructure repository.

## Adoption pattern (chain)

Each PEP keeps its own product-shape event struct and embeds `chain.Stamp`:

```go
import "github.com/dogukanturhal/hexx-pep-core/pkg/chain"

type Event struct {
    chain.Stamp
    Time     time.Time `json:"time"`
    Subject  string    `json:"subject,omitempty"`
    Action   string    `json:"action"`
    // ...product-specific fields...
}

// Optional: implement chain.TimeStamper if you want auto-stamped Time.
func (e *Event) StampTime(t time.Time) { if e.Time.IsZero() { e.Time = t } }

func main() {
    sink := chain.NewJSONLChain(os.Stdout)
    _ = sink.Emit(ctx, &Event{Action: "open", Subject: "..."})
    // Sink fills Stamp.Seq + Stamp.PrevHash before marshaling.
}
```

## Adoption pattern (identity)

```go
import "github.com/dogukanturhal/hexx-pep-core/pkg/identity"

func authorize(ctx context.Context, id identity.Identity, target Target) bool {
    return id.HasAnyRole(target.RequiredRoles...)
}
```

## Why a dedicated module

Considered and rejected:
- **`pkg/` subdir inside Talon or Jess** — distorts product ownership; creates a
  one-way dependency between the two PEPs.
- **Single `hexx-shared` mono-module** — grab-bag entropy; opposite of focused.

A third PEP (hypothetical `hexx-sftp-broker`, `hexx-mqtt-broker`) inherits both
primitives free.

## Adoption pattern (cryptoprofile)

Resolve the profile once at boot and hand the selected signer to `govdecision` —
flipping `SECURITY_PROFILE` changes the crypto with no other code change:

```go
import (
    "github.com/dogukanturhal/hexx-pep-core/pkg/cryptoprofile"
    "github.com/dogukanturhal/hexx-pep-core/pkg/govdecision"
)

prof, err := cryptoprofile.Resolve(os.Getenv("SECURITY_PROFILE")) // "" => enterprise
signer, err := cryptoprofile.Signer(prof, vaultIssuerPrivateKey)  // govdecision.Signer
signed, err := govdecision.Sign(signer, decision)

// TLS side: hybrid post-quantum KEX with a classical group alongside.
srv := &http.Server{TLSConfig: cryptoprofile.TLSConfig(prof)} // + Certificates
```

FIPS 140-3 mode is not selected here — it is a build/run flag:
`GOFIPS140=v1.0.0 go build ./...` plus `GODEBUG=fips140=on`. The seam only picks
FIPS-approved algorithms per profile (`cryptoprofile.FIPSApproved`), and
`cryptoprofile.FIPSMode` reports the runtime state without being able to change it.

## Compatibility

- Go 1.26+. (`pkg/cryptoprofile` uses the Go 1.24 `tls.X25519MLKEM768` and Go 1.26
  `tls.SecP384r1MLKEM1024` hybrid KEX constants and `crypto/fips140`; the module's
  `go` directive is `go 1.26`, matching the design's Go 1.26 cryptographic-module
  baseline. The other packages remain Go 1.23-compatible in isolation.)
- Hash-chain **algorithm** is bit-for-bit identical to the original Jess
  `internal/audit/JSONSink` (SHA-256 over the exact emitted line bytes
  including the trailing `\n`). A SOC analyst with the old verifier code can
  parse new traces; a new verifier can parse old traces.
- **Field order** in the JSON output differs from pre-migration Jess by one
  hop: `chain.Stamp` is embedded at the top of the product event struct, so
  `"seq"` and `"prev_hash"` appear at the START of each line instead of the
  end. Consumers that parse JSON (Wazuh, Loki LogQL, replay scripts) are
  unaffected. The hash-chain itself is internally consistent within each
  chain run; the natural boundary is pod restart on rollout (in-memory chain
  state starts fresh anyway), so no chain ever spans the migration in
  flight.
