# reality-pt

A [Tor pluggable transport](https://spec.torproject.org/pt-spec/) that borrows the TLS handshake of a real third-party website, in the style of [REALITY](https://github.com/XTLS/REALITY).

**Status: alpha.** The handshake, the client and server runners, and an end-to-end test through the real binaries pass in CI. It has not been run against a real Tor client or a real censor yet.

## Why

[WebTunnel](https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/webtunnel) hides Tor inside HTTPS, but the bridge operator needs a domain, a certificate, and a real website behind a reverse proxy. A REALITY-style transport removes that requirement. The bridge answers unauthenticated clients and active probes with the real handshake of a chosen cover site, and only a client that holds the bridge's public key and short ID gets the tunnel.

I found no Tor pluggable transport built this way when I searched (2026-10). Corrections are welcome.

## How it works

```
tor --SOCKS5--> reality-client ==TLS 1.3==> reality-server --> ORPort
                                                  ^ everyone else is forwarded to the cover site
```

The client sends a Chrome-shaped ClientHello (uTLS) with an AEAD-sealed token in the session ID. A bridge that recognizes the token answers with a TLS 1.3 handshake whose certificate is signed with the shared key. A client rejects any peer whose certificate does not carry that proof, so a cover site answering by mistake never receives Tor traffic.

## Layout

```
transport/            stage interfaces: ClientStage, ServerStage
transport/reality/    handshake, parameters, bridge-line arguments
internal/ptclient/    SOCKS listener and the client pipeline
internal/ptserver/    listener and the bridge pipeline
internal/relay/       bidirectional copy
internal/ptrun/       signals, stdin-close, accept backoff
shaper/               traffic shaping plug-in point (no-op for now)
cmd/                  reality-client, reality-server, reality-keygen
e2e/                  runs the binaries with the TOR_PT_* environment
```

Each connection goes through a fixed pipeline: dial, handshake, shape, relay. A new transport implements `transport.ClientStage` and `transport.ServerStage` and reuses the runners.

## Setup

Binaries for Linux, macOS, and Windows (amd64 and arm64) come from the GitHub Releases page once a version is tagged. Nothing needs to be built locally.

**Bridge operator**

1. Pick a cover site that supports TLS 1.3 and is reachable from the bridge.
2. Generate keys: `reality-keygen` prints a private key, a public key, and a short ID.
3. In `torrc`:

```
BridgeRelay 1
ORPort auto
ExtORPort auto
ServerTransportPlugin reality exec /usr/local/bin/reality-server
ServerTransportListenAddr reality 0.0.0.0:443
ServerTransportOptions reality private-key=<private-key> dest=<cover-host>:443 server-names=<cover-host> short-ids=<short-id>
```

Optional: `max-time-diff=2m` rejects clients whose clock differs by more than that.

**Client**

```
UseBridges 1
ClientTransportPlugin reality exec /usr/local/bin/reality-client
Bridge reality <bridge-ip>:443 <fingerprint> public-key=<public-key> short-id=<short-id> sni=<cover-host>
```

`fingerprint=chrome` is the default and the only profile for now. The server only accepts a ClientHello that offers an X25519MLKEM768 key share.

## Traffic shaping

`shaper.Shaper` wraps the tunnel connection on both ends after the handshake. The default is a no-op. Candidates to study: Vision-style padding against TLS-in-TLS patterns, obfs4 `iat-mode`, and learned shaping from the research literature.

## Development

CI runs on GitHub Actions: gofmt, `go vet`, tests with the race detector, and a cross-platform build. The `tidy` workflow runs `gofmt` and `go mod tidy` and commits the result, so no local Go toolchain is needed.

## License

BSD-3-Clause, see [LICENSE](LICENSE). `transport/reality/client.go` follows the Xray-core REALITY client and stays MPL-2.0. See [NOTICE.md](NOTICE.md).
