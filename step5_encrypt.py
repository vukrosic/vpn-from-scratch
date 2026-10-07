"""Step 5: encryption. Lock the inner packet with the shared key before it goes into the outer packet."""
import struct
from collections import Counter

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from packet import build, readable
from step1_packet import MESSAGE
from step4_keys import Identity


def seal(key, counter, inner):
    """The counter (8 bytes), the scrambled packet, and a 16-byte tag only a key holder can make."""
    number = struct.pack('<Q', counter)                      # a counter is used once per key, never twice
    return number + ChaCha20Poly1305(key).encrypt(b'\0\0\0\0' + number, inner, None)


def unseal(key, data):
    """(counter, packet), or None if the key is wrong or a single bit was changed on the way."""
    try:
        inner = ChaCha20Poly1305(key).decrypt(b'\0\0\0\0' + data[:8], data[8:], None)
        return struct.unpack('<Q', data[:8])[0], inner
    except InvalidTag:
        return None


def spread(data):
    """How many different byte values appear, and the share of the most common one."""
    counts = Counter(data)
    return len(counts), max(counts.values()) / len(data)


if __name__ == '__main__':
    key, back = Identity('laptop').keys_with(Identity('vpn server').public)
    inner = build('10.0.0.2', '203.0.113.5', 50001, 80, MESSAGE)
    sealed = seal(key, 0, inner)
    print(f'inner packet {len(inner)} bytes -> sealed {len(sealed)} bytes: 8 (counter) + {len(inner)} + 16 (tag)')
    print('before:', readable(inner))
    print('after: ', readable(sealed))
    print('after, as hex:', sealed[:24].hex(' '), '...')
    print('opened with the key:', unseal(key, sealed) == (0, inner))
    print('opened with another key:', unseal(back, sealed))
    flips = [sealed[:i // 8] + bytes([sealed[i // 8] ^ 1 << i % 8]) + sealed[i // 8 + 1:] for i in range(len(sealed) * 8)]
    print(f'flip one bit, any of the {len(flips)}: accepted {sum(unseal(key, f) is not None for f in flips)} times')
    plain = b''.join(build('10.0.0.2', '203.0.113.5', 50000 + i, 80, MESSAGE) for i in range(2000))
    locked = b''.join(seal(key, i, build('10.0.0.2', '203.0.113.5', 50000 + i, 80, MESSAGE))[8:] for i in range(2000))
    for name, data in (('plain ', plain), ('sealed', locked)):
        kinds, top = spread(data)
        print(f'2,000 packets, {name}: {kinds} of 256 byte values appear; the most common one is {top:.2%} of the bytes')
