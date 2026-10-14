# Changelog

All notable changes are listed here. The project follows [semantic versioning](https://semver.org/); before 1.0 anything may change.

## 0.1.0-alpha.1

First release.

- REALITY-style transport: browser-shaped ClientHello (uTLS), encrypted token, certificate signed with the shared key, strangers forwarded to a cover site.
- `reality-client`, `reality-server`, `reality-keygen` and `reality-check` (checks a cover site).
- Replay cache, `max-time-diff` (five minutes by default), client version limits, fallback rate limits, PROXY protocol for the cover.
- `padding` shaper (default) with opening decoy frames.
- Private bridge Docker image, deb/rpm/apk packages, signed checksums, SBOMs, build provenance.
- Tests with a real Tor bridge and client in CI, fuzzing, and a weekly check that the ClientHello profiles are current.

Known limits are in [docs/threat-model.md](docs/threat-model.md).
