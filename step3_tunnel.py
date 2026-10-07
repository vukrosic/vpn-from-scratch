"""Step 3: the tunnel. Put the whole packet inside another packet, addressed to a VPN server."""
from network import CAFE, LAPTOP, SITE, Laptop, Machine, Nat, Net, Router, Website
from packet import build, parse, readable, readdress, show
from step1_packet import MESSAGE

VPN, PORT = '198.51.100.7', 51820
INSIDE = '10.0.0.2'              # the laptop's second address, used only inside the tunnel


class TunnelLaptop(Laptop):
    """A laptop that sends every packet inside another packet, addressed to the VPN server."""

    def __init__(self, net, name, addr, router, server, inside=INSIDE):
        super().__init__(net, name, addr, router)
        self.server, self.app_addr = server, inside

    def pack(self, inner):
        return inner                      # step 7 replaces pack and unpack with encryption

    def unpack(self, data):
        return data

    def out(self, raw):
        super().out(build(self.addr, self.server, PORT, PORT, self.pack(raw)))

    def receive(self, raw):
        inner = self.unpack(parse(raw)['payload'])
        if inner is not None:
            super().receive(inner)


class VPNServer(Machine):
    """Opens the outer packet, sends the inner one on as its own. Answers go back the same way."""

    def __init__(self, net, name, addr):
        super().__init__(net, name, addr)
        self.nat, self.where, self.seen = Nat(60000), {}, []    # where: tunnel address -> outer (address, port)

    def pack(self, inner, client):
        return inner

    def unpack(self, data):
        return data

    def receive(self, raw):
        p = parse(raw)
        if p['dport'] == PORT:                                   # from a client: unwrap, send on
            inner = self.unpack(p['payload'])
            if inner is None:
                return
            q = parse(inner)
            self.where[q['src']] = (p['src'], p['sport'])
            self.seen.append(inner)
            port = self.nat.out(q['src'], q['sport'])
            self.net.send(readdress(inner, src=self.addr, sport=port), self)
        elif p['dport'] in self.nat.table:                       # an answer from the internet: wrap, send back
            addr, port = self.nat.table[p['dport']]
            there, their_port = self.where[addr]
            inner = readdress(raw, dst=addr, dport=port)
            self.net.send(build(self.addr, there, PORT, their_port, self.pack(inner, addr)), self)


def tunnel_cafe():
    """Step 2's setup plus a VPN server, with the laptop sending everything through it."""
    net = Net()
    router = Router(net, 'cafe', CAFE)
    server = VPNServer(net, 'vpn', VPN)
    laptop = TunnelLaptop(net, 'laptop', LAPTOP, router, VPN)
    return net, laptop, router, Website(net, 'site', SITE), server


if __name__ == '__main__':
    net, laptop, router, site, server = tunnel_cafe()
    answer = laptop.ask(SITE, MESSAGE)
    for sender, to, raw in net.log:
        print(f'  {sender:>7} -> {to:<7} {show(raw)}')
    outer = router.seen[0]
    print(f'the outer packet is {len(outer)} bytes: the inner {len(parse(outer)["payload"])} + 28 of new headers')
    print('the website saw a visitor from:', ', '.join(sorted(set(site.visitors))))
    print('the laptop got:', readable(answer))
    print('the cafe sees the packet go to', parse(outer)['dst'], 'but the inside is not locked:')
    print('  ', readable(parse(outer)['payload']))
    hidden = parse(parse(outer)['payload'])
    print('   it can read the inner packet too: to', hidden['dst'], '-', readable(hidden['payload']))
