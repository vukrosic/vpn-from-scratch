"""Step 4: a shared key. Two machines agree on a secret while the cafe listens to every byte."""
import hashlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def toy(p=23, g=5, a=6, b=15):
    """The idea with small numbers. Each side keeps one number secret and sends g to that power."""
    A, B = pow(g, a, p), pow(g, b, p)                 # these two travel in the open
    return A, B, pow(B, a, p), pow(A, b, p)           # each side raises the other's number to its own secret


def crack(p, g, A):
    """What a listener has to do: try every secret until g to that power gives A."""
    return next(x for x in range(1, p) if pow(g, x, p) == A)


class Identity:
    """A key pair: a private key that never leaves the machine, and a public key anyone may know."""

    def __init__(self, name=None):
        seed = hashlib.sha256(name.encode()).digest() if name else None    # a name gives the same demo key every run
        make = X25519PrivateKey
        self.private = make.from_private_bytes(seed) if seed else make.generate()
        self.public = self.private.public_key().public_bytes_raw()

    def keys_with(self, their_public):
        """Two 32-byte keys shared with the owner of `their_public`: (to send, to receive)."""
        secret = self.private.exchange(X25519PublicKey.from_public_bytes(their_public))
        both = HKDF(hashes.SHA256(), 64, salt=None, info=b'vpn-from-scratch').derive(secret)
        first, second = both[:32], both[32:]
        return (first, second) if self.public < their_public else (second, first)


if __name__ == '__main__':
    A, B, secret_a, secret_b = toy()
    print(f'toy numbers: p = 23, g = 5.  Laptop keeps 6, sends 5^6 mod 23 = {A}.  Server keeps 15, sends 5^15 mod 23 = {B}.')
    print(f'laptop: {B}^6 mod 23 = {secret_a}.   server: {A}^15 mod 23 = {secret_b}.   The same number.')
    print(f'a listener who saw {A} finds the laptop\'s secret by trying: {crack(23, 5, A)} tries')
    laptop, server = Identity('laptop'), Identity('vpn server')
    print('real keys (X25519), 32 bytes each:')
    print('  laptop public key ', laptop.public.hex())
    print('  server public key ', server.public.hex())
    send, receive = laptop.keys_with(server.public)
    their_send, their_receive = server.keys_with(laptop.public)
    print('  laptop -> server key, worked out by the laptop:', send.hex()[:24], '...')
    print('  laptop -> server key, worked out by the server:', their_receive.hex()[:24], '...')
    print('  both directions agree:', send == their_receive and receive == their_send, '  the two keys differ:', send != receive)
    print(f'  a private key is one number of up to {len(str(2 ** 255))} digits')
