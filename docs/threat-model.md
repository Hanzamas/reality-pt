# Threat model

This page says what the transport is built to resist, what it does not resist, and what has been measured. Nothing here has been tested against a real censor.

## What it resists

| Threat | How |
|---|---|
| Identifying the protocol by its handshake | The ClientHello comes from a uTLS browser profile (`chrome`, `safari`). A weekly job checks the Chrome profile against the current release. Safari has no automatic check. |
| Blocking "fully encrypted" traffic | The traffic is a real TLS 1.3 connection, not random bytes. |
| SNI allowlists | The SNI is that of a real cover site. |
| Active probing | A connection that does not prove knowledge of the bridge key is forwarded to the cover site. A test sends malformed probes to the bridge and to the cover and compares the answers byte for byte. |
| Replay of a captured ClientHello | The bridge remembers ClientHello randoms, and a repeat loses its token. Tokens also expire after `max-time-diff`, five minutes by default. |
| Detection by missing post-handshake records (the Aparecium check) | The bridge sends the same records after the handshake as the cover. A test compares them with a cover whose certificate the server can verify. |
| Using the bridge as a free relay to the cover | Forwarding to the cover is rate limited. |

## What it does not resist

- **TLS inside TLS.** Tor's link is TLS, so the tunnel carries a second handshake. Xue et al. (USENIX Security 2024) detect that pattern from record sizes and directions. The `padding` shaper hides runs of equal-size records. It does not hide who speaks when at the start of the connection. See the measurements below.
- **Traffic analysis in general.** Timing and volume are not shaped.
- **IP blocking.** A censor that learns the bridge address can block it.
- **A cover on another network.** The bridge presents a site that is hosted elsewhere. `reality-check -bridge-ip` compares the networks and warns. No source measures how much this matters.
- **A leaked private key.** Anyone with it can impersonate the bridge.
- **A recorded connection and a future quantum computer.** The outer handshake offers a hybrid key exchange, but the authentication key comes from X25519 alone.
- **Clock skew.** A client whose clock differs from the bridge by more than `max-time-diff` is turned away.
- **Anything in Tor itself.** This transport only covers the first hop.

## What was measured

The `lab` runs a bridge, a TLS server that stands in for Tor's link, and an HTTP/2 site that makes browsing, polling, download and upload visits. It records the TLS records of each connection. Three detectors, written for this project, look at the application data records after the tunnel's handshake.

Share of sessions flagged, at a threshold set so that about 5% of the comparison sessions are flagged:

| Detector | No shaper | Padding | Comparison traffic |
|---|---|---|---|
| equal-size records | 0.00 | 0.00 | 0.00 |
| template of an unshaped tunnel | 1.00 | 1.00 | 0.03 |
| template that includes shaped tunnels | 1.00 | 1.00 | 0.05 |

How to read it:

- The comparison traffic is synthetic and the detectors are simple. The numbers show whether shaping moves anything a censor could use. They do not predict what a real censor does.
- Against the comparison traffic used here, the equal-size detector does not separate the tunnel at all, so it says nothing about padding. An earlier run with only page-load traffic did separate it, and padding brought it from 1.00 to 0.00.
- The template detectors find the tunnel with or without padding. That matches the paper: padding changes sizes, not the round trips at the start.

A shaper that resists this has to make the opening exchange follow the distribution of real traffic. That needs real traces and is not done.

## Operating advice

- Give the bridge line only to the people it is for. A published line can be blocked.
- Pick a cover site that speaks TLS 1.3 and sits on the bridge's network. Run `reality-check` first.
- Keep the server and client clocks right.
- Keep uTLS current. An old browser profile is a fingerprint of its own.
