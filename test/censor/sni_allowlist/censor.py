# A stand-in for an SNI allowlist, the kind of rule some censors run: a TLS
# connection is dropped unless its server name is on the list. REALITY was
# built to pass this by using the name of a real, allowed site.
#
# CensorLab runs the top level of this file once per connection.

from tls import parse_client_hello

ALLOWED = [b"cover.test"]


def process(packet):
    if not packet.tcp:
        return None
    try:
        hello = parse_client_hello(packet.payload)
    except Exception:
        # Not a ClientHello: application data, a server flight, or no TLS.
        return None
    if hello.sni and hello.sni.lower() not in ALLOWED:
        return "drop"
    return None
