# reality-pt

A [Tor pluggable transport](https://spec.torproject.org/pt-spec/) that borrows the TLS handshake of a real website, in the style of [REALITY](https://github.com/XTLS/REALITY).

**Status: alpha.** A real Tor bridge and a real Tor client work through it in CI, on a runner with no censor in the way. It has not been tested against a real censor, and the shaper does not hide the start of the connection from a censor that looks for TLS inside TLS. Read the [threat model](docs/threat-model.md) before relying on it.

## Why

[WebTunnel](https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/webtunnel) hides Tor inside HTTPS, but the operator needs a domain, a certificate and a website behind a reverse proxy. Here the bridge answers strangers and active probes with the real handshake of a cover site it does not own, and only a client that holds the bridge's public key gets the tunnel. I found no Tor transport built this way when I searched (2026-10). Corrections are welcome.

```
tor --SOCKS5--> reality-client ==TLS 1.3==> reality-server --> tor (bridge)
                                                  ^ everyone else is forwarded to the cover site
```

## Quick start

**Run a bridge** (Docker holds Tor and the transport, and prints the bridge line):

```
docker run -d --name reality-bridge -p 443:443 -v reality-bridge:/var/lib/tor \
  -e REALITY_DEST=www.example.com:443 -e PUBLIC_IP=203.0.113.7 \
  ghcr.io/hanzamas/reality-pt-bridge
docker logs reality-bridge
```

Pick the cover with `reality-check` first. The full guide, with the options and the non-Docker setup, is in [docs/operating-a-bridge.md](docs/operating-a-bridge.md).

**Use a bridge.** Install the `reality-pt` package or unpack an archive from the Releases page, then add the line from the operator to `torrc`:

```
UseBridges 1
ClientTransportPlugin reality exec /usr/bin/reality-client
Bridge reality <ip>:443 <fingerprint> public-key=<public-key> short-id=<short-id> sni=<cover-host> shaper=padding
```

Tor Browser and Orbot ship their transports inside the app, so a transport that is not bundled needs manual setup there. Getting it bundled upstream is the only route to a one-click setup.

## Documentation

| | |
|---|---|
| [Operating a bridge](docs/operating-a-bridge.md) | choose a cover, run, options |
| [Threat model](docs/threat-model.md) | what it resists, what it does not, what was measured |
| [Architecture](docs/architecture.md) | the pipeline, the packages, what is reused |
| [Testing](docs/testing.md) | what CI checks and what it cannot |
| [Contributing](CONTRIBUTING.md), [Security](SECURITY.md), [Changelog](CHANGELOG.md) | |

## License

BSD-3-Clause, see [LICENSE](LICENSE). `transport/reality/client.go` follows the Xray-core REALITY client and stays MPL-2.0. See [NOTICE.md](NOTICE.md).
