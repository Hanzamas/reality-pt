# Testing

Nothing needs to be built or run on your own machine. Every check runs on GitHub Actions.

## What runs

| Workflow | Runs on | What it checks |
|---|---|---|
| `ci` | Linux, Windows, macOS | gofmt, `go vet`, lint, all tests (race detector on Linux), a cross-platform snapshot release with packages and SBOMs |
| `tor-e2e` | Linux | a real Tor bridge and a real Tor client reach each other through the transport and fetch a page; the Docker bridge image does the same and keeps its keys and identity across a restart |
| `fuzz` | Linux | the parsers that read untrusted input |
| `freshness` | Linux, weekly | the ClientHello profiles against the current Chrome and Firefox |
| `tidy` | manual | runs gofmt and `go mod tidy`, can upgrade modules, commits the result |
| `release` | on a `v*` tag | archives, packages, checksums, signatures, SBOMs, provenance, and the bridge image |

## What the tests cover

- The handshake with every ClientHello profile, against the real REALITY server.
- A wrong key and a wrong short ID are rejected.
- A prober sees the cover's certificate, and malformed probes get byte-identical answers from the bridge and from the cover.
- The bridge sends the same post-handshake records as the cover.
- The real client and server binaries, run with the `TOR_PT_*` environment, carry a SOCKS5 connection to an echo ORPort, with and without the shaper.
- Replay, version limits, fallback limits and option parsing.
- The shapers round-trip data, keep frames inside one TLS record, and survive garbage input.
- The lab measures what stand-in detectors see (see the threat model).

## What cannot be tested here

A GitHub runner sits in a US datacenter with no censor on the path. Nothing in CI shows how a real censor reacts. That needs a machine inside a censored network. A self-hosted runner there, started by hand or on a schedule and never by pull requests, would do it.

## Running one thing by hand

Use the Actions tab, or:

```
gh workflow run ci.yml
gh workflow run tor-e2e.yml
gh workflow run tidy.yml -f get=github.com/refraction-networking/utls@master
```
