# Contributing

## Ground rules

- Reuse before you write. goptlib, `xtls/reality` and uTLS do the hard parts. A new dependency needs a reason.
- Keep a change small and one-purpose. Open a pull request, not a push to `main`.
- A claim in the docs needs a test or a source. If a limit is known, say so.
- Never log a client address, and never publish a secret. `PublicArgs` is the only thing that leaves the server.

## No local build needed

CI builds and tests everything on Linux, Windows and macOS, and runs real Tor. You do not need a Go toolchain: push a branch and read the run. If gofmt or `go.mod` need fixing, run the `tidy` workflow on your branch.

## Checks a pull request must pass

`ci` (gofmt, `go vet`, lint, tests, snapshot release) and `tor-e2e` (real Tor). `fuzz` runs on changes to `transport/`.

## Style

- Plain Go, formatted with gofmt. Comments say why, not what.
- Errors are wrapped with `%w` and start with the package or transport name.
- Tests sit next to the code, and a test that needs the network or real Tor says so and skips itself.
- A bug fix comes with a test that fails without it.

## Licensing

New files are BSD-3-Clause. A file ported from an MPL-2.0 project keeps the MPL-2.0 header and is listed in [NOTICE.md](NOTICE.md).
