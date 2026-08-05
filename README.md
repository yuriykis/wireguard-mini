# Mini WireGuard

> [!WARNING]
> Work in progress. This is a hobby project, not a production-ready
> WireGuard implementation or a replacement for WireGuard.

Mini WireGuard is a userspace implementation of the WireGuard protocol written
from scratch in Go.

## Current state

The program currently:

- creates a Linux TUN interface named `tun0` using `IFF_TUN | IFF_NO_PI`;
- parses and validates IPv4 packets;
- forwards IPv4 packets read from TUN as UDP payloads to a configured peer;
- includes tested helpers for parsing ICMP echo requests and building replies;
- validates and calculates IPv4 and ICMP checksums.

Unit tests cover packet parsing, checksum calculation, and echo reply creation.

```sh
go test ./...
```

## TODO

- Send IP packets between two network namespaces through an unencrypted UDP
  tunnel.
- Add the WireGuard Noise IK handshake and authenticated encryption.
- Test interoperability with the kernel WireGuard implementation.
