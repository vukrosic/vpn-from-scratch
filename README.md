# VPN from scratch

A small VPN in plain Python, built in eight steps: one packet by hand, a tiny simulated internet, a tunnel, a key exchange, encryption, a replay window, a server for more than one device, and a real UDP socket.
Seven files, 508 lines, plus step scripts and tests. One library: `cryptography`.

Companion code for the video "How a VPN Works — Build One From Scratch".

**This is a program for learning. Do not use it to protect real traffic.** See "What it leaves out".

## Run it

```bash
pip install cryptography
bash run_all.sh
```

That runs every step and the exercise in a few seconds (`demo-output.txt` is one saved run). Python 3.9+.

```bash
python3 tests.py
```

## What it shows

A laptop on coffee-shop Wi-Fi sends a 59-byte packet with a login in it.

|  | no VPN | with the VPN |
| --- | --- | --- |
| the coffee shop sees the destination | 203.0.113.5 (the website) | 198.51.100.7 (the VPN server) |
| the coffee shop reads the login | yes, all 31 bytes | no, 119 bytes of noise |
| the website sees the visitor as | 192.0.2.44 (the coffee shop) | 198.51.100.7 (the VPN server) |
| the VPN server sees | nothing | the tunnel address, the website and every byte |

A VPN does not remove trust. It moves it from the network you are on to a server you chose.

## The steps

| File | What it adds |
| --- | --- |
| `packet.py` | Build and parse an IPv4 + UDP packet by hand, with the header checksum |
| `network.py` | Machines, a wire you can listen on, and a router that rewrites addresses (NAT) |
| `step1_packet.py` | One packet, byte by byte: 20 + 8 + 31 = 59 bytes |
| `step2_network.py` | Laptop, coffee shop, website: what the router can read |
| `step3_tunnel.py` | A packet inside a packet. The website now sees the VPN server; the bytes are still readable |
| `step4_keys.py` | Two machines agree on a secret key while someone listens (toy numbers first, then X25519 + HKDF) |
| `step5_encrypt.py` | Seal each packet with ChaCha20-Poly1305: a counter as the nonce, a 16-byte tag |
| `step6_replay.py` | A 64-packet sliding window that drops packets sent twice |
| `step7_vpn.py` | All of it together, for two devices, with three attacks that fail |
| `step8_real_socket.py` | The same sealed packets through the operating system's UDP socket, with timing |
| `exercise_leak.py` | The exercise |
| `tests.py` | Checks for every step |

The sealed packet layout (type, client number, counter, sealed bytes) follows the WireGuard data message: 16 bytes in front, 16 bytes of tag behind, so a 1,400-byte packet becomes 1,432 bytes.

On the laptop that made the video, step 8 measured 51,251 round trips per second without encryption and 24,270 sealed, about 5.1 millionths of a second to seal and open one packet. Your numbers will differ.

## The exercise

In `exercise_leak.py` the tunnel is up and the login is sealed, and the coffee shop still learns which site you visit:

```bash
python3 exercise_leak.py
```

```
the name server was asked by: 192.0.2.44
packets that skipped the tunnel: 1
```

Find out why, fix `LeakyLaptop`, and compare with the fixed version:

```bash
python3 exercise_leak.py fixed
```

## What it leaves out

- The keys never change. A real VPN runs a handshake and makes fresh keys every few minutes.
- The network is simulated inside one Python program. A real VPN gets its packets from the operating system through a virtual network card, which needs administrator rights.
- The inner packets are UDP only.

## License

MIT
