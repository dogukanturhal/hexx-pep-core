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

## Keep pull requests small

This project has one maintainer who reads every line before merging. Large pull requests can't be reviewed properly, so they are not accepted.

- **One change per pull request.** One bug fix, one feature, or one refactor. Don't mix formatting or unrelated clean-ups into it.
- **Size limit: 400 changed lines and 15 files** (additions plus deletions; `go.sum`, `package-lock.json`, `Cargo.lock` and generated files don't count). Aim for under 200. An automated check fails pull requests over the limit.
- **Bigger change? Open an issue first.** Describe the plan and we'll agree on how to split it into a series of small pull requests that each build and pass tests on their own.
- Exceptions (for example, a large test fixture) only with a maintainer's agreement in the issue.

## AI-assisted contributions

You may use AI tools, under these conditions:

- **Say so** in the pull request description, and name what the tool did (for example "tests drafted with an AI assistant, then reviewed and edited").
- **You are the author.** You must understand every line and be able to explain and change it during review. "The tool wrote it" is not an answer to a review question.
- **Same rules as everyone:** the size limit above, tests, and the licence/sign-off requirements. You confirm you have the right to submit the code.
- Pull requests that look generated without review (code that doesn't fit the codebase, invented APIs, a PR description that doesn't match the diff, or no answers to review questions) are closed without detailed review.

## How your contribution lands

This GitHub repository is a mirror of our main development repository. When a pull request is merged here, we import it there with your authorship and sign-off preserved, and it comes back in the next sync. You don't need to do anything extra.

## Reporting bugs and asking questions

Use the issue templates. For security problems, follow [SECURITY.md](SECURITY.md)
instead of opening a public issue.

## Licence

By contributing you agree that your contribution is licensed under the
repository's licence (see `LICENSE`).
