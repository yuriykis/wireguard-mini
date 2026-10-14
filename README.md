# Mini WireGuard

> [!WARNING]
> This is a learning project, not production code and not a replacement for
> WireGuard. Use the real WireGuard for anything that matters.

Mini WireGuard is a userspace implementation of the WireGuard protocol, written
from scratch in Go to understand how the protocol works. It connects two IPv4
peers with an encrypted point-to-point tunnel and interoperates with the Linux
kernel WireGuard implementation: a kernel `wg` interface completes the
handshake with it in both roles and exchanges traffic through the tunnel.

Cryptographic primitives come from `golang.org/x/crypto`: Curve25519,
ChaCha20-Poly1305, BLAKE2s and HKDF built on HMAC-BLAKE2s.

## How it works

The program creates a TUN interface named `tun0` (`IFF_TUN | IFF_NO_PI`),
assigns it the configured IPv4 address, sets the MTU to `1420` so that an
encapsulated packet still fits in a 1500-byte underlay frame, and opens one UDP
socket for all traffic to the peer.

### Handshake

The peer marked as initiator sends a handshake initiation when it starts. The
responder answers with a handshake response. Both messages follow WireGuard's
Noise IK pattern:

- the initiation (148 bytes) carries the initiator's ephemeral public key, its
  static public key encrypted to the responder, and an encrypted TAI64N
  timestamp;
- the response (92 bytes) carries the responder's ephemeral public key and an
  authentication tag over an empty payload, which proves the responder holds
  its private key;
- both messages carry MAC1, which the receiver checks before doing any
  expensive cryptography; MAC2 is always zero, because cookies are not
  implemented.

Each side picks a random sender index and learns the peer's index from the
handshake. At the end, both sides derive the same pair of transport keys from
the final chaining key: one for sending and one for receiving.

### Transport

Two goroutines run the tunnel, one per direction:

- **TUN → UDP:** an IPv4 packet read from `tun0` is encrypted with
  ChaCha20-Poly1305 under the sending key and a 64-bit counter, and sent to the
  peer as a transport data message addressed with the peer's index;
- **UDP → TUN:** a transport data message is decrypted with the receiving key,
  its counter is checked against a 64-packet anti-replay window, and the
  decrypted IPv4 packet is written to `tun0`.

Incoming datagrams are dispatched by message type. A datagram that is too short,
has an unknown type or fails verification is dropped without any reply.

### Limitations

- IPv4 only; IPv6 packets read from `tun0` are ignored.
- Exactly one peer, given by its endpoint and public key.
- The handshake runs once, at startup. There are no timers: no handshake
  retransmission, keepalives or rekeying.
- No cookies, no preshared key, no `wg`-compatible configuration interface.

## Configuration

Each peer gets a JSON file with its role, its own private key and the peer's
public key, both as base64-encoded 32-byte Curve25519 keys (the format used by
`wg genkey` and `wg pubkey`):

```json
{
    "initiator": true,
    "privateKey": "<base64 private key>",
    "peerPublicKey": "<base64 peer public key>"
}
```

Addresses are given as flags:

| flag | meaning |
|---|---|
| `-listen` | local UDP address, for example `192.0.2.1:51820` |
| `-peer` | peer UDP endpoint, for example `192.0.2.2:51820` |
| `-tun-address` | IPv4 address of `tun0`, for example `10.0.0.1/24` |
| `-config` | path to the JSON file above |

## Running

The program is Linux-only and needs permission to create and configure a TUN
interface, for example by running the built binary with `sudo`.

`lab.sh` builds a two-host setup on one machine: two network namespaces,
`wgmini-left` (`192.0.2.1`) and `wgmini-right` (`192.0.2.2`), joined by a
`veth` pair.

```sh
mage build
./lab.sh up
```

Start the responder first, because the initiator sends its handshake only once:

```sh
sudo ip netns exec wgmini-right ./bin/wireguard-mini \
  -listen 192.0.2.2:51820 \
  -peer 192.0.2.1:51820 \
  -tun-address 10.0.0.2/24 \
  -config configs/right.json
```

Then the initiator:

```sh
sudo ip netns exec wgmini-left ./bin/wireguard-mini \
  -listen 192.0.2.1:51820 \
  -peer 192.0.2.2:51820 \
  -tun-address 10.0.0.1/24 \
  -config configs/left.json
```

Traffic between `10.0.0.1` and `10.0.0.2` now goes through the tunnel:

```sh
sudo ip netns exec wgmini-left ping 10.0.0.2
```

Capturing on `tun0` shows the plaintext IP packets, and capturing on `veth-left`
shows only encrypted UDP datagrams on port 51820.

### With kernel WireGuard

Either side can be replaced by a kernel WireGuard interface. For example, as the
responder in `wgmini-right`:

```sh
sudo ip -n wgmini-right link add wg0 type wireguard
sudo ip netns exec wgmini-right sh -c 'cat keys/right.key | wg set wg0 \
  listen-port 51820 private-key /dev/stdin \
  peer <left public key> allowed-ips 10.0.0.1/32 endpoint 192.0.2.1:51820'
sudo ip -n wgmini-right addr add 10.0.0.2/24 dev wg0
sudo ip -n wgmini-right link set wg0 up
```

On Ubuntu, the AppArmor profile for `wg` only lets it read keys from
`/etc/wireguard/`, which is why the key is piped from a root shell.

`./lab.sh down` removes the setup.

## Development

Run all unit tests:

```sh
mage test
```

Run the linters:

```sh
mage lint
```
