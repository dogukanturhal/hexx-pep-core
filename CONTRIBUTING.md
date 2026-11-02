# Contributing to hexx-pep-core

Thanks for taking the time. Small fixes (a bug, a typo, a test) can go straight
to a pull request. For anything larger, such as a new package, an exported API
change or a behaviour change, open an issue first so we can agree on the shape
before you write the code.

## Developer Certificate of Origin

Every commit must carry a `Signed-off-by` trailer. It certifies that you wrote
the change or have the right to submit it under the project's licence, as
described at https://developercertificate.org/.

```sh
git commit -s -m "fix: describe the change"
```

The trailer is added from your `user.name` and `user.email`. If you forgot it,
run `git commit --amend --signoff --no-edit` and force-push your branch.
Maintainers will not merge unsigned commits.

## Development

You need a Go toolchain matching the version in `go.mod`.

```sh
go vet ./...
go test -race ./...
golangci-lint run ./...      # uses .golangci.yml when present
```

Run these in each Go module of the repository (some repositories contain more
than one). CI runs the same commands plus `govulncheck` and CodeQL.

## Pull requests

- Keep a change focused; unrelated cleanups go in a separate pull request.
- Add or update tests for behaviour you change.
- Update `CHANGELOG.md` under **Unreleased** for anything a user would notice.
- Do not commit credentials, tokens or customer data, even as test fixtures. Use
  obviously fake values.
- Commit messages: a short imperative summary line, then a body explaining why
  when the reason is not obvious.

## Reporting bugs and asking questions

Use the issue templates. For security problems, follow [SECURITY.md](SECURITY.md)
instead of opening a public issue.

## Licence

By contributing you agree that your contribution is licensed under the
repository's licence (see `LICENSE`).
