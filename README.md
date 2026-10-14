# reality-pt

A [Tor pluggable transport](https://spec.torproject.org/pt-spec/) that borrows the TLS handshake of a real third-party website, in the style of [REALITY](https://github.com/XTLS/REALITY).

**Status: design stage. Nothing works yet.** This repository currently holds the project layout, CI, and the traffic shaping interface.

## Idea

[WebTunnel](https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/webtunnel) hides Tor inside HTTPS, but the bridge operator needs a domain, a certificate, and a real website behind a reverse proxy. A REALITY-style transport removes that requirement: the bridge answers unauthenticated clients and active probes with the real handshake of a chosen cover site, and only a client holding the bridge's public key and short ID gets the tunnel.

I found no Tor pluggable transport built this way when I searched (2026-10). Corrections are welcome.

## Plan

```
tor --SOCKS5--> [client PT] ==REALITY / TLS 1.3==> [server PT] --> ORPort
                                                    ^ probes are forwarded to the cover site
```

| Part | Reuse |
|---|---|
| PT protocol (managed proxy) | [goptlib](https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/goptlib) |
| REALITY server | [github.com/xtls/reality](https://github.com/XTLS/REALITY) (MPL-2.0) |
| REALITY client | Logic ported from Xray-core `transport/internet/reality/reality.go` (MPL-2.0) |
| Browser ClientHello | [uTLS](https://github.com/refraction-networking/utls) (BSD-3-Clause) |
| Project layout, server loop | Modeled on WebTunnel (BSD-3-Clause) |

Tor opens one PT connection per OR connection, so no stream multiplexer is planned.

### Traffic shaping

`shaper.Shaper` wraps the tunnel connection on both ends after the handshake. The default is a no-op. Candidates to study: Vision-style padding against TLS-in-TLS patterns, obfs4 `iat-mode`, and learned shaping from the research literature.

## Build

CI runs on GitHub Actions. There is nothing to build locally.

## License

BSD-3-Clause, see [LICENSE](LICENSE). Files ported from MPL-2.0 projects will keep the MPL-2.0 license and carry their own headers.
