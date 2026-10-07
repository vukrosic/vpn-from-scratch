"""Step 7: the whole VPN. The tunnel, the keys, the encryption and the replay window, for several clients."""
import struct

from network import CAFE, LAPTOP, SITE, Net, Router, Website
from packet import build, parse, readable, show
from step1_packet import MESSAGE
from step3_tunnel import INSIDE, PORT, VPN, TunnelLaptop, VPNServer
from step4_keys import Identity
from step5_encrypt import seal, unseal
from step6_replay import Window

DATA = b'\x04\0\0\0'                 # message type 4, "data", then three empty bytes: WireGuard's layout


class Peer:
    """One end's notes about the other end: two keys, a counter, a window, its tunnel address."""

    def __init__(self, me, their_public, number, inside=None, guard=True):
        self.send_key, self.receive_key = me.keys_with(their_public)
        self.number, self.inside, self.guard = number, inside, guard
        self.counter, self.window = 0, Window()
        self.refused = {'forged': 0, 'replay': 0, 'address': 0}

    def pack(self, inner):
        """type (4 bytes) + peer number (4) + counter (8) + sealed packet + tag (16)."""
        self.counter += 1
        return DATA + struct.pack('<I', self.number) + seal(self.send_key, self.counter - 1, inner)

    def unpack(self, data):
        """The inner packet, or None. The tag is checked first: only a real packet moves the window."""
        opened = unseal(self.receive_key, data[8:])
        if opened is None:
            self.refused['forged'] += 1
        elif self.guard and not self.window.fresh(opened[0]):
            self.refused['replay'] += 1
        elif self.inside and parse(opened[1])['src'] != self.inside:
            self.refused['address'] += 1               # a client may only use its own tunnel address
        else:
            return opened[1]


class SecureLaptop(TunnelLaptop):
    def __init__(self, net, name, addr, router, server, me, server_public, number, inside=INSIDE):
        super().__init__(net, name, addr, router, server, inside)
        self.peer = Peer(me, server_public, number)

    def pack(self, inner):
        return self.peer.pack(inner)

    def unpack(self, data):
        return self.peer.unpack(data) if data[:4] == DATA else None


class SecureServer(VPNServer):
    def __init__(self, net, name, addr, me, guard=True):
        super().__init__(net, name, addr)
        self.me, self.guard, self.peers, self.unknown = me, guard, {}, 0

    def add(self, their_public, inside):
        """Let one client in: its public key and the tunnel address it gets. Returns its number."""
        number = len(self.peers) + 1
        self.peers[number] = Peer(self.me, their_public, number, inside, self.guard)
        return number

    def pack(self, inner, client):
        return next(p for p in self.peers.values() if p.inside == client).pack(inner)

    def unpack(self, data):
        known = data[:4] == DATA and len(data) >= 32
        peer = self.peers.get(struct.unpack('<I', data[4:8])[0]) if known else None
        if peer is None:
            self.unknown += 1
            return None
        return peer.unpack(data)


def secure_cafe(guard=True, kind=SecureLaptop):
    """A laptop on the cafe's Wi-Fi and a phone on mobile data, both clients of one VPN server."""
    net = Net()
    cafe, mobile = Router(net, 'cafe', CAFE), Router(net, 'mobile', '192.0.2.201')
    site = Website(net, 'site', SITE)
    server = SecureServer(net, 'vpn', VPN, Identity('vpn server'), guard)
    me, phone_me = Identity('laptop'), Identity('phone')
    number = server.add(me.public, INSIDE)
    laptop = kind(net, 'laptop', LAPTOP, cafe, VPN, me, server.me.public, number)
    phone = SecureLaptop(net, 'phone', '172.16.5.9', mobile, VPN, phone_me, server.me.public,
                         server.add(phone_me.public, '10.0.0.3'), '10.0.0.3')
    return net, laptop, phone, cafe, site, server


if __name__ == '__main__':
    net, laptop, phone, cafe, site, server = secure_cafe()
    answer = laptop.ask(SITE, MESSAGE)
    for sender, to, raw in net.log:
        print(f'  {sender:>7} -> {to:<7} {show(raw)}')
    outer = cafe.seen[0]
    print(f'on the Wi-Fi: {len(outer)} bytes = 20 + 8 (outer headers) + 16 (type, number, counter) + 59 (inner) + 16 (tag)')
    print('the laptop got:', readable(answer), '  the phone got:', readable(phone.ask(SITE, b'GET /news')))
    print('WHO SEES WHAT')
    print('  cafe      to', parse(outer)['dst'], ' message readable:', MESSAGE in outer, ' site address inside:', bytes([203, 0, 113, 5]) in outer)
    print('  website   visitors from', ', '.join(sorted(set(site.visitors))))
    print('  vpn       ', show(server.seen[0]))
    print('ATTACKS FROM THE CAFE')
    recorded = net.log[1][2]                                    # the laptop's packet as it left the cafe
    before = len(site.got)
    for _ in range(3):
        net.send(recorded, cafe)
    net.run()
    print('  replay the recorded packet 3 times: the site got', len(site.got) - before, 'more;', server.peers[1].refused)
    net.send(recorded[:-1] + bytes([recorded[-1] ^ 1]), cafe)
    net.send(build(CAFE, VPN, 40000, PORT, DATA + struct.pack('<I', 9) + bytes(83)), cafe)
    net.run()
    print('  flip one bit; invent a packet for client 9:', server.peers[1].refused, ' unknown client:', server.unknown)
    phone.app_addr = INSIDE                                     # the phone claims the laptop's tunnel address
    print('  the phone uses the laptop\'s tunnel address: answer', phone.ask(SITE, b'GET /mail'), server.peers[2].refused)
    net2, laptop2, _, cafe2, site2, server2 = secure_cafe(guard=False)
    laptop2.ask(SITE, b'PAY 5 coins to the cafe')
    for _ in range(3):
        net2.send(net2.log[1][2], cafe2)
    net2.run()
    print('  with the window switched off, the same replay: the site got', site2.got.count(b'PAY 5 coins to the cafe'), 'payments from 1')
