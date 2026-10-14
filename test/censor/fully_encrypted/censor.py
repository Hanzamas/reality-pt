# A stand-in for the rule the Great Firewall applies to fully encrypted
# traffic, after Wu et al., "How the Great Firewall of China Detects and
# Blocks Fully Encrypted Traffic" (USENIX Security 2023).
#
# It looks only at the first data packet of a connection. The packet passes if
# any exemption matches, and is dropped otherwise:
#   1. the average number of set bits per byte is 3.4 or less, or 4.6 or more
#   2. the first six bytes are printable ASCII
#   3. more than half of the bytes are printable ASCII
#   4. there is a run of more than twenty printable bytes
#   5. it starts like TLS or HTTP
#
# This is written from the paper's description. It is an approximation, and
# a real censor may differ.
#
# CensorLab runs the top level of this file once per connection, so the state
# below belongs to one connection.

checked = False


def printable(b):
    return 0x20 <= b <= 0x7E


def known_protocol(payload):
    if len(payload) >= 3 and payload[1] == 3 and payload[0] in (0x14, 0x15, 0x16, 0x17):
        return True
    for prefix in (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"HTTP/"):
        if payload[: len(prefix)] == prefix:
            return True
    return False


def process(packet):
    global checked
    if not packet.tcp or packet.payload_len == 0 or checked:
        return None
    checked = True

    payload = packet.payload
    bits = packet.payload_avg_popcount
    if bits <= 3.4 or bits >= 4.6:
        return None
    if len(payload) >= 6 and all(printable(b) for b in payload[:6]):
        return None

    printable_count = 0
    run = 0
    longest = 0
    for b in payload:
        if printable(b):
            printable_count += 1
            run += 1
            longest = max(longest, run)
        else:
            run = 0
    if printable_count * 2 > len(payload) or longest > 20:
        return None
    if known_protocol(payload):
        return None
    return "drop"
