# reality-pt

A [Tor pluggable transport](https://spec.torproject.org/pt-spec/) that borrows the TLS handshake of a real third-party website, in the style of [REALITY](https://github.com/XTLS/REALITY).

**Status: alpha.** A real Tor 0.4 bridge and a real Tor client bootstrap through it in CI and fetch a page over the Tor network. It has not been tested against a real censor.

## Why

[WebTunnel](https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/webtunnel) hides Tor inside HTTPS, but the bridge operator needs a domain, a certificate, and a real website behind a reverse proxy. A REALITY-style transport removes that requirement. The bridge answers unauthenticated clients and active probes with the real handshake of a chosen cover site, and only a client that holds the bridge's public key and short ID gets the tunnel.

I found no Tor pluggable transport built this way when I searched (2026-10). Corrections are welcome.

## How it works

```
tor --SOCKS5--> reality-client ==TLS 1.3==> reality-server --> ORPort
                                                  ^ everyone else is forwarded to the cover site
```

The client sends a browser-shaped ClientHello (uTLS) with an AEAD-sealed token in the session ID. A bridge that recognizes the token answers with a TLS 1.3 handshake whose certificate is signed with the shared key. A client rejects any peer whose certificate does not carry that proof, so a cover site answering by mistake never receives Tor traffic.

## Run a bridge

One command, with Docker. The image holds Tor and the transport and prints the bridge line for your users:

```
docker run -d --name reality-bridge -p 443:443 -v reality-bridge:/var/lib/tor \
  -e REALITY_DEST=www.microsoft.com:443 -e PUBLIC_IP=203.0.113.7 \
  ghcr.io/hanzamas/reality-pt-bridge
docker logs reality-bridge
```

Pick a cover site that speaks TLS 1.3 and is reachable from the server. Keys and the Tor identity live in the volume, so the line stays the same after a restart. The bridge is private: it is not published, you hand the line to the people you want to serve.

Without Docker, install the `reality-pt` package (deb, rpm, apk) or an archive from the Releases page, run `reality-keygen`, and add to `torrc`:

```
BridgeRelay 1
ORPort auto
ExtORPort auto
ServerTransportPlugin reality exec /usr/bin/reality-server
ServerTransportListenAddr reality 0.0.0.0:443
ServerTransportOptions reality private-key=<private-key> dest=<cover-host>:443 server-names=<cover-host> short-ids=<short-id>
```

`reality-server` writes the bridge line to `<DataDirectory>/pt_state/reality_bridge_line.txt`. Optional: `max-time-diff=2m` rejects clients whose clock differs by more than that.

## Use a bridge

Install the `reality-pt` package or unpack an archive, then add to `torrc` with the line from the operator:

```
UseBridges 1
ClientTransportPlugin reality exec /usr/bin/reality-client
Bridge reality <bridge-ip>:443 <fingerprint> public-key=<public-key> short-id=<short-id> sni=<cover-host>
```

`fingerprint=` selects the ClientHello profile and is optional. If a distribution's AppArmor profile stops Tor from starting the client, allow that path in the profile.

Tor Browser and Orbot ship their transports inside the app, so a transport that is not bundled needs manual setup there. Getting it bundled upstream is the only route to a true one-click setup.

## ClientHello profiles

The server only accepts a ClientHello that offers an X25519MLKEM768 key share and a 32-byte session ID. These profiles pass against the real server in CI:

| name | follows |
|---|---|
| `chrome` (default) | newest Chrome profile in uTLS |
| `safari` | newest Safari profile in uTLS, no automatic freshness check |

Firefox is not offered: uTLS has no profile for a recent Firefox, and the weekly freshness check found its newest profile ten releases behind. An old profile is a fingerprint of its own, so it is better absent.

The `freshness` workflow compares the profiles with the current Chrome and Firefox releases every week and opens an issue when one has drifted.

## What the tests prove

- Handshake with every profile, wrong key and wrong short ID rejected, against the real REALITY server.
- A prober sees the cover site's certificate, and malformed probes get byte-identical answers from the bridge and from the cover site.
- The real client and server binaries, run with the `TOR_PT_*` environment, carry a SOCKS5 connection to an echo ORPort.
- A real Tor bridge and a real Tor client reach each other through the transport (extended ORPort included) and fetch a page over the Tor network.
- The Docker image starts, keeps its keys and identity across a restart, and serves a real Tor client.

A GitHub runner sits in a US datacenter with no censor on the path, so none of this shows how a real censor reacts. That needs a machine inside a censored network.

## Layout

```
transport/            stage interfaces: ClientStage, ServerStage
transport/reality/    handshake, parameters, bridge-line arguments
internal/ptclient/    SOCKS listener and the client pipeline
internal/ptserver/    listener, bridge pipeline, bridge line file
internal/relay/       bidirectional copy
internal/ptrun/       signals, stdin-close, accept backoff
shaper/               traffic shaping plug-in point (no-op for now)
cmd/                  reality-client, reality-server, reality-keygen
docker/, Dockerfile   private bridge image
scripts/              real Tor test scripts
e2e/                  runs the binaries with the TOR_PT_* environment
```

Each connection goes through a fixed pipeline: dial, handshake, shape, relay. A new transport implements `transport.ClientStage` and `transport.ServerStage` and reuses the runners.

## Traffic shaping

`shaper.Shaper` wraps the tunnel connection on both ends after the handshake. The default is a no-op. Candidates to study: Vision-style padding against TLS-in-TLS patterns, obfs4 `iat-mode`, and learned shaping from the research literature.

## Development

Nothing needs to be built locally. CI runs on GitHub Actions: gofmt, `go vet`, tests with the race detector, and a cross-platform snapshot release with packages (`ci`); real Tor and Docker bridge tests (`tor-e2e`). The `tidy` workflow runs `gofmt` and `go mod tidy`, can upgrade modules, and commits the result. Pushing a `v*` tag publishes archives, packages, and the bridge image.

## License

BSD-3-Clause, see [LICENSE](LICENSE). `transport/reality/client.go` follows the Xray-core REALITY client and stays MPL-2.0. See [NOTICE.md](NOTICE.md).
