"""Step 8: a real socket. The same sealed packets, carried by the operating system's own UDP."""
import socket
import sys
import threading
import time

from packet import build
from step3_tunnel import INSIDE
from step4_keys import Identity
from step5_encrypt import seal, unseal
from step7_vpn import Peer

HOST = '127.0.0.1'                                   # this computer talking to itself: no admin rights needed
INNER = build(INSIDE, '203.0.113.5', 50001, 80, bytes(1372))    # one full-size inner packet: 1,400 bytes


def serve(sock, peer):
    """The server's loop: take a datagram, open it, check it, send the packet back sealed."""
    while True:
        data, who = sock.recvfrom(2048)
        if data == b'stop':
            return
        inner = peer.unpack(data) if peer else data
        if inner is not None:
            sock.sendto(peer.pack(inner) if peer else inner, who)


def trips(n, locked=True):
    """Send n packets to the server, wait for each to come back. Returns seconds, count, one datagram."""
    me, them = Identity('laptop'), Identity('vpn server')
    mine = Peer(me, them.public, 1) if locked else None
    theirs = Peer(them, me.public, 1, INSIDE) if locked else None
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind((HOST, 0))                           # port 0: the system picks a free port
    there = server.getsockname()
    threading.Thread(target=serve, args=(server, theirs), daemon=True).start()
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.settimeout(2)
    start, ok, first = time.perf_counter(), 0, b''
    for i in range(n):
        datagram = mine.pack(INNER) if locked else INNER
        first = first or datagram
        client.sendto(datagram, there)
        back = client.recvfrom(2048)[0]
        ok += (mine.unpack(back) if locked else back) == INNER
    seconds = time.perf_counter() - start
    client.sendto(b'stop', there)
    return seconds, ok, first


if __name__ == '__main__':
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 20000
    plain, ok_plain, _ = trips(n, locked=False)
    locked, ok, datagram = trips(n)
    print(f'one sealed datagram: {len(datagram)} bytes = 16 + {len(INNER)} + 16.  It starts:', datagram[:20].hex(' '))
    print(f'{n:,} round trips through a real UDP socket, {len(INNER):,}-byte packets')
    print(f'  no encryption: {plain:5.2f} s   {n / plain:>7,.0f} round trips per second   {ok_plain:,} came back right')
    print(f'  sealed:        {locked:5.2f} s   {n / locked:>7,.0f} round trips per second   {ok:,} came back right')
    key = Identity('laptop').keys_with(Identity('vpn server').public)[0]
    start = time.perf_counter()
    for i in range(n):
        unseal(key, seal(key, i, INNER))
    alone = time.perf_counter() - start
    print(f'  sealing and opening alone: {alone / n * 1e6:.1f} millionths of a second per packet, {n * len(INNER) / alone / 1e6:,.0f} MB per second')
    extra = len(datagram) - len(INNER) + 28
    print(f'  extra bytes per packet: {extra} of {len(INNER) + extra} on the wire = {extra / (len(INNER) + extra):.1%}')
