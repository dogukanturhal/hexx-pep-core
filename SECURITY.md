# Security policy

hexx-pep-core is a library other services link into, so a flaw here can reach every
service that imports it. Please report vulnerabilities privately.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting:

1. Open the **Security** tab of https://github.com/dogukanturhal/hexx-pep-core.
2. Choose **Report a vulnerability** and fill in the advisory form.

If you cannot use GitHub, email **dogukanturhal@hexxlock.com**.

Please include:

- What the issue is and which package or function is affected.
- The version or commit you tested.
- A reproduction: a small program or test is ideal.
- Your view of the impact: who can trigger it and what they gain.
- Whether you want to be credited in the advisory.

Do not open a public issue, pull request or discussion for a suspected
vulnerability.

## What to expect

- We acknowledge a report within **three business days**.
- We aim to confirm or reject it, with an initial severity, within **ten
  business days**.
- We aim to publish a fix and advisory within **90 days** of the report, sooner
  for severe issues. If a fix needs more time we will tell you why and agree on
  a new date with you rather than set one unilaterally.
- Reporters are credited in the advisory unless they ask not to be. There is
  no bug bounty.

## Supported versions

The project is pre-1.0. Only the latest tagged release (and `main`) receives
security fixes.

## Scope

In scope: code in this repository. Out of scope: vulnerabilities in third-party
dependencies that do not affect this code (report them upstream; Dependabot and
`govulncheck` in CI track them), and misconfiguration in an application that
uses the library.
