"""One IPv4 packet with a UDP message inside, built and read by hand.

bytes 0-19   the IP header: who sends, who receives, how long, a checksum
bytes 20-27  the UDP header: which program sends (its port), which program receives, how long
bytes 28-    the payload: the message itself
"""
import socket
import struct


def checksum(data):
    """Add the bytes up as 16-bit numbers, fold the overflow back in, flip every bit."""
    if len(data) % 2:
        data += b'\0'
    total = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def build(src, dst, sport, dport, payload, ttl=64):
    """The bytes of one packet: 20 bytes of IP header, 8 of UDP header, then the payload."""
    udp = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload   # the last 0: UDP checksum not used
    head = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 0, 0, ttl, 17, 0,
                       socket.inet_aton(src), socket.inet_aton(dst))
    return head[:10] + struct.pack('!H', checksum(head)) + head[12:] + udp


def parse(raw):
    """Read a packet back into its fields. A packet with a wrong header checksum is refused."""
    if len(raw) < 28 or raw[0] != 0x45 or raw[9] != 17:
        raise ValueError('not an IPv4 + UDP packet')
    if checksum(raw[:20]) != 0:
        raise ValueError('bad header checksum')
    length = struct.unpack('!H', raw[2:4])[0]
    sport, dport = struct.unpack('!HH', raw[20:24])
    src, dst = socket.inet_ntoa(raw[12:16]), socket.inet_ntoa(raw[16:20])
    return {'src': src, 'dst': dst, 'sport': sport, 'dport': dport, 'ttl': raw[8], 'length': length,
            'payload': raw[28:length]}


def readdress(raw, **changes):
    """The same packet with some fields replaced, for example a new source address."""
    p = {**parse(raw), **changes}
    return build(p['src'], p['dst'], p['sport'], p['dport'], p['payload'], p['ttl'])


def readable(data):
    """What a person can read in the bytes: letters and digits stay, everything else is a dot."""
    return ''.join(chr(b) if 32 <= b < 127 else '.' for b in data)


def show(raw):
    """One line for a log: from, to, size, and the readable part of the payload."""
    p = parse(raw)
    route = f"{p['src']}:{p['sport']} -> {p['dst']}:{p['dport']}"
    return f"{route}  {len(raw)} bytes  {readable(p['payload'])[:48]}"
