"""A tiny internet inside one program: a laptop, a cafe's Wi-Fi router and a website.

Machines hand packets (real bytes, from packet.py) to each other. Every hop is written to a log.
"""
from collections import deque

from packet import build, parse, readdress

LAPTOP, CAFE_INSIDE, CAFE = '192.168.1.23', '192.168.1.1', '192.0.2.44'
SITE = '203.0.113.5'


class Net:
    """The wires between the machines that have a public address."""

    def __init__(self):
        self.machines, self.queue, self.log = {}, deque(), []

    def send(self, raw, sender, via=None):
        """Put a packet on the wire. `via` is the next machine on the way; without it, the destination itself."""
        self.queue.append((raw, sender, via))

    def run(self):
        """Carry packets until nothing is left to carry."""
        while self.queue:
            raw, sender, via = self.queue.popleft()
            to = via or self.machines.get(parse(raw)['dst'])
            self.log.append((sender.name, to.name if to else 'nowhere', raw))
            if to:
                to.receive(raw)


class Machine:
    def __init__(self, net, name, addr, router=None):
        self.net, self.name, self.addr, self.router = net, name, addr, router
        if router is None:
            net.machines[addr] = self              # a public address: anyone can send to it
        else:
            router.inside[addr] = self             # a private address: only its router knows it

    def receive(self, raw):
        pass


class Nat:
    """A router's notebook: which inside (address, port) is behind each of its own ports."""

    def __init__(self, first=40000):
        self.first, self.ports, self.table = first, {}, {}

    def out(self, addr, port):
        mine = self.ports.setdefault((addr, port), self.first + len(self.ports))
        self.table[mine] = (addr, port)
        return mine


class Router(Machine):
    """The cafe's Wi-Fi box. Inside addresses are private, so on the way out it writes its own address on the
    packet, and on the way back it looks up who asked. Whoever runs it can read all that passes: self.seen."""

    def __init__(self, net, name, addr):
        super().__init__(net, name, addr)
        self.inside, self.nat, self.seen = {}, Nat(), []

    def receive(self, raw):
        p = parse(raw)
        self.seen.append(raw)
        if p['dst'] != self.addr:                                   # going out
            port = self.nat.out(p['src'], p['sport'])
            self.net.send(readdress(raw, src=self.addr, sport=port), self)
        elif p['dport'] in self.nat.table:                          # an answer coming back
            addr, port = self.nat.table[p['dport']]
            self.net.send(readdress(raw, dst=addr, dport=port), self, via=self.inside[addr])


class Website(Machine):
    """Answers every message with the address it came from. Keeps a visitor list."""

    def __init__(self, net, name, addr):
        super().__init__(net, name, addr)
        self.visitors, self.got = [], []

    def receive(self, raw):
        p = parse(raw)
        self.visitors.append(p['src'])
        self.got.append(p['payload'])
        answer = b'hello ' + p['src'].encode()
        self.net.send(build(self.addr, p['src'], p['dport'], p['sport'], answer), self)


class Laptop(Machine):
    def __init__(self, net, name, addr, router):
        super().__init__(net, name, addr, router)
        self.app_addr, self.inbox, self.asked = addr, [], 0

    def out(self, raw):
        """Every packet the laptop sends goes to its router first."""
        self.net.send(raw, self, via=self.router)

    def receive(self, raw):
        self.inbox.append(parse(raw)['payload'])

    def ask(self, dst, message, dport=80):
        """An app sends one message and waits for the answer. None if no answer comes."""
        self.asked += 1
        before = len(self.inbox)
        self.out(build(self.app_addr, dst, 50000 + self.asked, dport, message))
        self.net.run()
        return self.inbox[-1] if len(self.inbox) > before else None


def cafe():
    """The setup of step 2: a laptop on the cafe's Wi-Fi, and a website out on the internet."""
    net = Net()
    router = Router(net, 'cafe', CAFE)
    return net, Laptop(net, 'laptop', LAPTOP, router), router, Website(net, 'site', SITE)
