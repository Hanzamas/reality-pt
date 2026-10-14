# Architecture

reality-pt is a Tor [pluggable transport](https://spec.torproject.org/pt-spec/). Tor starts it as a helper process and talks to it through the managed proxy protocol.

```
tor --SOCKS5--> reality-client ==TLS 1.3==> reality-server --ExtORPort--> tor (bridge)
                                                  |
                                                  +-- anyone else is forwarded to the cover site
```

## The pipeline

Every connection goes through the same four stages, on both sides.

| Stage | Client | Server |
|---|---|---|
| dial | TCP to the bridge | accept TCP |
| handshake | REALITY handshake with a browser-shaped ClientHello | REALITY handshake, strangers are forwarded to the cover |
| shape | wrap the tunnel with the bridge's shaper | same shaper |
| relay | copy between Tor's SOCKS connection and the tunnel | copy between the tunnel and the ORPort |

A new transport implements `transport.ClientStage` and `transport.ServerStage` and reuses the runners.

## Packages

| Path | Role |
|---|---|
| `cmd/` | `reality-client`, `reality-server`, `reality-keygen`, `reality-check` |
| `transport/` | the stage interfaces |
| `transport/reality/` | the handshake, parameters, replay cache, bridge-line arguments |
| `shaper/` | traffic shaping: `none` and `padding` |
| `internal/pt/client`, `internal/pt/server` | the runners on top of goptlib |
| `internal/pt/relay`, `internal/pt/lifecycle` | the copy loop, signals, accept backoff |
| `internal/doctor` | checks a site as a cover (`reality-check`) |
| `internal/measure/` | lab and detectors that measure what a censor sees |
| `test/` | end-to-end tests and the scripts that run real Tor |
| `docker/`, `Dockerfile` | the private bridge image |

## What is reused

| Part | From | License |
|---|---|---|
| Tor managed-proxy protocol | goptlib | public domain |
| Server handshake | `github.com/xtls/reality` | MPL-2.0 |
| Client handshake | ported from the Xray-core REALITY client | MPL-2.0 |
| Browser ClientHello | uTLS | BSD-3-Clause |

See [NOTICE.md](../NOTICE.md).

## Decisions

- **One PT connection per Tor connection.** Tor opens one connection to the bridge per OR connection, so there is no stream multiplexer.
- **The bridge picks the shaper.** Both ends must frame traffic the same way, so the server publishes `shaper=` in the bridge line and the client follows it.
- **Replay protection sits in front of the library.** The REALITY server cannot be asked about replays, so a listener wrapper remembers ClientHello randoms and damages the token of a repeat. The library then treats it as a stranger and forwards it to the cover.
- **Secrets never leave the server.** `PublicArgs` is the only thing published, and a test checks that it holds no private key.
