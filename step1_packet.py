"""Step 1: a packet. Everything on the internet travels as packets: a header with addresses, then the message."""
from packet import build, parse, readable

MESSAGE = b'LOGIN sam password=tuna-melt-42'

if __name__ == '__main__':
    raw = build('192.168.1.23', '203.0.113.5', 50001, 80, MESSAGE)
    print(f'one packet, {len(raw)} bytes = 20 (IP header) + 8 (UDP header) + {len(MESSAGE)} (message)')
    print('IP header   ', raw[:20].hex(' '))
    print('  sender    ', raw[12:16].hex(' '), ' =', '.'.join(str(b) for b in raw[12:16]))
    print('  receiver  ', raw[16:20].hex(' '), ' =', '.'.join(str(b) for b in raw[16:20]))
    print('  checksum  ', raw[10:12].hex(' '))
    print('UDP header  ', raw[20:28].hex(' '))
    print('message     ', raw[28:].hex(' '))
    print('as text     ', readable(raw[28:]))
    print('read back:  ', parse(raw))
    broken = raw[:15] + bytes([raw[15] ^ 1]) + raw[16:]          # one bit of the sender's address flipped
    try:
        parse(broken)
    except ValueError as e:
        print('one bit flipped in the header:', e)
