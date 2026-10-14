# Operating a bridge

A bridge is a Tor relay that is not listed publicly, with `reality-server` as its transport. This page is for the person who runs one.

## 1. Pick a cover site

The bridge copies the handshake of a real site. The site must speak TLS 1.3 and negotiate X25519 or X25519MLKEM768, and it should be on the bridge's network. Check before you start:

```
reality-check -dest www.example.com:443 -bridge-ip 203.0.113.7
```

It reports the TLS version, the key exchange, HTTP/2, the certificate, and whether the cover and the bridge share a network (a Team Cymru DNS lookup).

## 2. Run it

With Docker, which holds Tor and the transport and prints the bridge line:

```
docker run -d --name reality-bridge -p 443:443 -v reality-bridge:/var/lib/tor \
  -e REALITY_DEST=www.example.com:443 -e PUBLIC_IP=203.0.113.7 \
  ghcr.io/hanzamas/reality-pt-bridge
docker logs reality-bridge
```

Keys and the Tor identity live in the volume, so the line is the same after a restart.

Without Docker, install the `reality-pt` package (deb, rpm, apk), run `reality-keygen`, and add to `torrc`:

```
BridgeRelay 1
PublishServerDescriptor 0
ORPort auto
ExtORPort auto
ServerTransportPlugin reality exec /usr/bin/reality-server
ServerTransportListenAddr reality 0.0.0.0:443
ServerTransportOptions reality private-key=<private-key> dest=www.example.com:443 server-names=www.example.com short-ids=<short-id>
```

`reality-server` writes the bridge line to `<DataDirectory>/pt_state/reality_bridge_line.txt`. Fill in the address and the fingerprint (from `<DataDirectory>/fingerprint`).

## Options

Set these in `ServerTransportOptions reality ...`.

| Option | Default | Meaning |
|---|---|---|
| `private-key` | required | X25519 private key from `reality-keygen`. Keep it secret. |
| `dest` | required | cover site as `host:port` |
| `server-names` | required | comma-separated SNI values clients may use, all served by `dest` |
| `short-ids` | required | comma-separated hex IDs, 2 to 16 digits each |
| `shaper` | `padding` | `padding`, `morph` or `none`. Published in the bridge line, and the client follows it. `morph` is experimental: it makes the start of the tunnel follow a real connection, adds delay at the start, and needs client and bridge built from the same release. |
| `max-time-diff` | `5m` | clock difference allowed between client and bridge. `0` turns the check off, which also lets old tokens be replayed for longer. |
| `min-client-version`, `max-client-version` | unset | `major.minor.patch` range of protocol versions to accept |
| `proxy-protocol` | off | `1` or `2` to send a PROXY header to the cover, for a cover you run |
| `fallback-after` | 2 MiB | bytes per direction that pass at full speed when a stranger is forwarded to the cover |
| `fallback-rate`, `fallback-burst` | 1 MiB/s, 2 MiB | rate and bucket size after that. `fallback-rate=0` turns the limit off. |

## What the client needs

```
UseBridges 1
ClientTransportPlugin reality exec /usr/bin/reality-client
Bridge reality <ip>:443 <fingerprint> public-key=<public-key> short-id=<short-id> sni=<cover-host> shaper=padding
```

The line printed by the bridge already has all of it. `fingerprint=` is optional and picks the ClientHello profile.

## Notes

- If a distribution's AppArmor profile stops Tor from starting the transport, allow `/usr/bin/reality-server` in it.
- The first connection after a start can be slow: the server measures the cover's handshake in the background.
- Run `PublishServerDescriptor 0` and hand the line out yourself. A published bridge is easier to find and block.
