"""Checks for every step. Run: python3 tests.py"""
import struct

from network import CAFE, SITE, cafe
from packet import build, checksum, parse, readdress
from step1_packet import MESSAGE
from step3_tunnel import INSIDE, PORT, VPN, tunnel_cafe
from step4_keys import Identity, crack, toy
from step5_encrypt import seal, unseal
from step6_replay import Window
from step7_vpn import DATA, secure_cafe
from step8_real_socket import trips

# step 1: a packet survives the round trip, and one flipped bit is refused
raw = build('192.168.1.23', SITE, 50001, 80, MESSAGE)
p = parse(raw)
assert len(raw) == 59 and (p['src'], p['dst'], p['sport'], p['dport'], p['payload']) == ('192.168.1.23', SITE, 50001, 80, MESSAGE)
assert checksum(raw[:20]) == 0 and parse(readdress(raw, src='10.0.0.2'))['src'] == '10.0.0.2'
try:
    parse(raw[:8] + bytes([raw[8] ^ 1]) + raw[9:])
    raise SystemExit('a damaged header was accepted')
except ValueError:
    pass

# step 2: without a VPN the cafe reads the message and the site sees the cafe's address
net, laptop, router, site = cafe()
assert laptop.ask(SITE, MESSAGE) == b'hello ' + CAFE.encode() and site.visitors == [CAFE]
assert MESSAGE in router.seen[0] and len(net.log) == 4

# step 3: the tunnel changes the address the site sees, and hides nothing
net, laptop, router, site, server = tunnel_cafe()
assert laptop.ask(SITE, MESSAGE) == b'hello ' + VPN.encode() and site.visitors == [VPN]
assert parse(router.seen[0])['dst'] == VPN and MESSAGE in router.seen[0] and len(router.seen[0]) == 59 + 28

# step 4: both sides get the same keys; a stranger gets different ones
A, B, s1, s2 = toy()
assert s1 == s2 == 2 and crack(23, 5, A) == 6
a, b, c = Identity('laptop'), Identity('vpn server'), Identity('cafe')
assert a.keys_with(b.public) == b.keys_with(a.public)[::-1] and c.keys_with(b.public) != a.keys_with(b.public)
assert Identity().public != Identity().public

# step 5: sealed packets open only with the right key and only if no bit changed
key, other = a.keys_with(b.public)
sealed = seal(key, 7, raw)
assert unseal(key, sealed) == (7, raw) and unseal(other, sealed) is None and len(sealed) == len(raw) + 24
assert all(unseal(key, sealed[:i] + bytes([sealed[i] ^ 1]) + sealed[i + 1:]) is None for i in range(len(sealed)))
assert MESSAGE not in sealed

# step 6: every counter is accepted once
w = Window()
assert [w.fresh(n) for n in [0, 1, 1, 3, 2, 2, 100, 37, 36, 100, 99, 99]] == [1, 1, 0, 1, 1, 0, 1, 1, 0, 0, 1, 0]

# step 7: the cafe learns nothing, replays and forgeries are dropped, two clients share the server
net, laptop, phone, router, site, server = secure_cafe()
assert laptop.ask(SITE, MESSAGE) == b'hello ' + VPN.encode() and phone.ask(SITE, b'hi') == b'hello ' + VPN.encode()
outer = router.seen[0]
assert MESSAGE not in outer and len(outer) == 59 + 60 and parse(outer)['dst'] == VPN
assert [parse(x)['src'] for x in server.seen] == [INSIDE, '10.0.0.3']
got = len(site.got)
for _ in range(5):
    net.send(net.log[1][2], router)
net.send(build(CAFE, VPN, 40000, PORT, DATA + struct.pack('<I', 1) + bytes(83)), router)
net.run()
assert len(site.got) == got and server.peers[1].refused == {'forged': 1, 'replay': 5, 'address': 0}
phone.app_addr = INSIDE
assert phone.ask(SITE, b'hi') is None and server.peers[2].refused['address'] == 1
assert laptop.ask(SITE, b'again') == b'hello ' + VPN.encode()          # the laptop still works after the attacks

# step 8: the same messages cross a real UDP socket
assert trips(50)[1] == 50 and trips(50, locked=False)[1] == 50

print('all tests passed')
