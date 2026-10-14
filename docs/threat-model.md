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

- **TLS inside TLS.** Tor's link is TLS, so the tunnel carries a second handshake. Xue et al. (USENIX Security 2024) detect that pattern from record sizes and directions. The `padding` shaper hides runs of equal-size records and nothing else. The `morph` shaper, which follows the opening of a real connection, helps against a censor that does not know it and not against one that does. It adds delay at the start of a connection. See the measurements below.
- **Traffic analysis in general.** Timing and volume are not shaped.
- **IP blocking.** A censor that learns the bridge address can block it.
- **A cover on another network.** The bridge presents a site that is hosted elsewhere. `reality-check -bridge-ip` compares the networks and warns. No source measures how much this matters.
- **A leaked private key.** Anyone with it can impersonate the bridge.
- **A recorded connection and a future quantum computer.** The outer handshake offers a hybrid key exchange, but the authentication key comes from X25519 alone.
- **Clock skew.** A client whose clock differs from the bridge by more than `max-time-diff` is turned away.
- **Anything in Tor itself.** This transport only covers the first hop.

## What was measured

Two experiments, both on a GitHub runner with local traffic. They run in CI (`ci`, step "Measurements") and print their numbers.

### Against real traffic

The `traces` workflow visited 19 real sites over HTTP/2 and saved the size and direction of the first application data records after the handshake: 152 traces, no content and no addresses (`shaper/data/real-openings.json`). The sites are split in two. The `morph` shaper may follow openings of one half. The other half is the comparison traffic, which the shaper never saw.

A tunnel carries a TLS connection to a stand-in for Tor's link and 40 to 80 cells. Two censors, written for this project, compare the first ten records of a connection with known examples and flag it if it is closer than all but 5% of the comparison traffic:

- **naive:** it knows how an unshaped tunnel starts.
- **adaptive:** it has also seen tunnels of the shaper being tested.

Share of tunnels flagged (the numbers move by about 0.2 from run to run):

| Shaper | Naive censor | Adaptive censor |
|---|---|---|
| none | 1.00 | 1.00 |
| `padding` | 1.00 | 1.00 |
| `morph` | 0.40 to 0.45 | 0.60 to 0.90 |
| real traffic the shapers never saw (false alarms) | 0.03 | 0.00 to 0.14 |

How to read it:

- `padding` changes sizes and not who speaks when, so a censor that matches on the opening exchange still finds every tunnel. This is what Xue et al. (USENIX Security 2024) predict.
- `morph` follows a real opening record by record, in the same order, so the first records look like an ordinary HTTP/2 connection. It roughly halves what the naive censor flags. It does not hide the tunnel from a censor that has seen it.
- The reason is visible in the printed samples: a morph tunnel is an exact copy of one of the shipped openings, and the list is public. A censor can hold the same list. A real connection from another site rarely matches one exactly, so exact matches stand out.
- The detectors are simple and the tunnel is a stand-in for Tor. These numbers show whether shaping changes what can be seen. They do not predict what a real censor does.

### Against static censors

`test/censor/run.sh` records four scenarios and replays them through two censor emulators built on [CensorLab](https://censorlab.cs.umass.edu/): the fully-encrypted-traffic rule after Wu et al. (2023) and an SNI allowlist. Each emulator acts on its own control (random bytes, a listed server name) and leaves the tunnel and ordinary browsing alone. The emulators are written from the papers and may differ from the real rules.

## Next steps for the shaper

- Follow the openings of the cover site itself, so the opening and the SNI agree. Tracked in [#7](https://github.com/Hanzamas/reality-pt/issues/7). The operator would collect them from the cover with the same tool that made `real-openings.json`.
- Carry the chosen opening in the client's first frame, so the two ends need no shared list and a version mismatch cannot break a connection. Today they must be built with the same list, and the server refuses a client whose list differs.
- Measure with more real traffic: more sites, video and file transfers, and traffic from a censored network.

## Operating advice

- Give the bridge line only to the people it is for. A published line can be blocked.
- Pick a cover site that speaks TLS 1.3 and sits on the bridge's network. Run `reality-check` first.
- Keep the server and client clocks right.
- Keep uTLS current. An old browser profile is a fingerprint of its own.
