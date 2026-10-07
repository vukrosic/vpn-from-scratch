"""Exercise: the DNS leak. The tunnel is up, yet the cafe still learns which site you visit. Find out how.

python3 exercise_leak.py          the leak
python3 exercise_leak.py fixed    the answer
"""
import sys

from network import SITE, Laptop, Machine
from packet import build, parse, readable, readdress, show
from step1_packet import MESSAGE
from step7_vpn import SecureLaptop, secure_cafe

NAMES = '203.0.113.53'               # a name server: it turns a name like bank.example into an address


class NameServer(Machine):
    def __init__(self, net, name, addr):
        super().__init__(net, name, addr)
        self.asked = []

    def receive(self, raw):
        p = parse(raw)
        self.asked.append(p['src'])
        answer = b'bank.example is at ' + SITE.encode()
        self.net.send(build(self.addr, p['src'], 53, p['sport'], answer), self)


class LeakyLaptop(SecureLaptop):
    """Web traffic goes through the tunnel. Name lookups (port 53) go straight onto the Wi-Fi."""

    def out(self, raw):
        if parse(raw)['dport'] == 53:
            Laptop.out(self, readdress(raw, src=self.addr))
        else:
            super().out(raw)

    def receive(self, raw):
        if parse(raw)['sport'] == 53:
            Laptop.receive(self, raw)
        else:
            super().receive(raw)


if __name__ == '__main__':
    fixed = sys.argv[1:] == ['fixed']
    net, laptop, phone, cafe, site, server = secure_cafe(kind=SecureLaptop if fixed else LeakyLaptop)
    names = NameServer(net, 'names', NAMES)
    print('the laptop asks for the address:', readable(laptop.ask(NAMES, b'where is bank.example?', 53)))
    print('the laptop logs in:', readable(laptop.ask(SITE, MESSAGE)))
    print('everything the cafe carried for the laptop:')
    for raw in cafe.seen:
        print('  ', show(raw))
    print('the name server was asked by:', names.asked[0])
    print('packets that skipped the tunnel:', sum(parse(raw)['dport'] == 53 for raw in cafe.seen))
