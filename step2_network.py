"""Step 2: no VPN. The laptop talks to a website through the cafe's Wi-Fi. Who sees what?"""
from network import SITE, cafe
from packet import readable, show
from step1_packet import MESSAGE


def report(net, router, site):
    """Print every hop, then what the cafe and the website each learned."""
    for sender, to, raw in net.log:
        print(f'  {sender:>7} -> {to:<7} {show(raw)}')
    print('the cafe can read:')
    for raw in router.seen[:1]:
        print('   to', show(raw).split(' -> ')[1])
    print('the website saw a visitor from:', ', '.join(sorted(set(site.visitors))))


if __name__ == '__main__':
    net, laptop, router, site = cafe()
    answer = laptop.ask(SITE, MESSAGE)
    report(net, router, site)
    print('the laptop got:', readable(answer))
