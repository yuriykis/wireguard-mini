package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net/netip"
	"os"
	"syscall"
	"unsafe"
)

const (
	tunsetiff = 0x400454ca // TUNSETIFF from <linux/if_tun.h>
	iffTun    = 0x0001     // IFF_TUN
	iffNoPI   = 0x1000     // IFF_NO_PI

	ipv4Version             = 4
	ipv4MinimumHeaderLength = 20
	protocolICMP            = 1
)

type ifreq struct {
	name  [16]byte
	flags uint16
	_     [22]byte
}

type ipv4Packet struct {
	headerLength int
	totalLength  int
	protocol     uint8
	source       netip.Addr
	destination  netip.Addr
	payload      []byte
}

func main() {
	file, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	var req ifreq
	copy(req.name[:], "tun0")
	req.flags = iffTun | iffNoPI

	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		file.Fd(),
		tunsetiff,
		uintptr(unsafe.Pointer(&req)), // should be directly here, not p := uintptr(unsafe.Pointer(&req))
	)
	if errno != 0 {
		log.Fatal(errno)
	}
	log.Print("tun0 created, Ctrl-C to remove it")

	buf := make([]byte, 65535)

	for {
		n, err := file.Read(buf)
		if err != nil {
			log.Fatal(err)
		}

		packet, err := parseIPv4Packet(buf[:n])
		if err != nil {
			log.Printf("invalid packet: %v", err)
			continue
		}

		log.Printf(
			"read=%d totalLength=%d version=%d headerLength=%d protocol=%d source=%s destination=%s",
			n,
			packet.totalLength,
			ipv4Version,
			packet.headerLength,
			packet.protocol,
			packet.source,
			packet.destination,
		)

		if packet.protocol == protocolICMP {
			if len(packet.payload) < 2 {
				log.Printf("invalid ICMP packet: missing type or code")
				continue
			}

			icmpType := packet.payload[0]
			icmpCode := packet.payload[1]

			log.Printf("ICMP type=%d code=%d", icmpType, icmpCode)
		}
	}
}

func parseIPv4Packet(data []byte) (ipv4Packet, error) {
	if len(data) < ipv4MinimumHeaderLength {
		return ipv4Packet{}, fmt.Errorf("packet too short: %d bytes", len(data))
	}

	version := int(data[0] >> 4)
	if version != ipv4Version {
		return ipv4Packet{}, fmt.Errorf("ignoring IP version %d", version)
	}

	headerLength := int(data[0]&0x0f) * 4
	if headerLength < ipv4MinimumHeaderLength {
		return ipv4Packet{}, fmt.Errorf("invalid IPv4 header length: %d bytes", headerLength)
	}
	if headerLength > len(data) {
		return ipv4Packet{}, fmt.Errorf("truncated IPv4 header: need %d bytes, got %d", headerLength, len(data))
	}

	if checksum := internetChecksum(data[:headerLength]); checksum != 0 {
		return ipv4Packet{}, fmt.Errorf(
			"invalid IPv4 header checksum: %#04x",
			checksum,
		)
	}

	totalLength := int(binary.BigEndian.Uint16(data[2:4]))
	if totalLength < headerLength {
		return ipv4Packet{}, fmt.Errorf("invalid IPv4 total length: %d, header length: %d", totalLength, headerLength)
	}
	if totalLength > len(data) {
		return ipv4Packet{}, fmt.Errorf("truncated IPv4 packet: expected %d bytes, got %d", totalLength, len(data))
	}

	return ipv4Packet{
		headerLength: headerLength,
		totalLength:  totalLength,
		protocol:     data[9],
		source:       netip.AddrFrom4([4]byte(data[12:16])),
		destination:  netip.AddrFrom4([4]byte(data[16:20])),
		payload:      data[headerLength:totalLength],
	}, nil
}

func internetChecksum(data []byte) uint16 {
	var sum uint32

	for len(data) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
	}

	if len(data) == 1 {
		sum += uint32(data[0]) << 8
	}

	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}

	return ^uint16(sum)
}
