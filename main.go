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
)

type ifreq struct {
	name  [16]byte
	flags uint16
	_     [22]byte
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

		version, headerLength, protocol, totalLength, err := validatePacket(buf[:n])
		if err != nil {
			log.Printf("invalid packet: %v", err)
			continue
		}

		source := netip.AddrFrom4([4]byte(buf[12:16]))
		destination := netip.AddrFrom4([4]byte(buf[16:20]))

		log.Printf(
			"read=%d totalLength=%d version=%d headerLength=%d protocol=%d source=%s destination=%s",
			n,
			totalLength,
			version,
			headerLength,
			protocol,
			source,
			destination,
		)

		if protocol == 1 { // ICMP
			if totalLength < headerLength+2 {
				log.Printf("invalid ICMP packet: missing type or code")
				continue
			}

			icmpType := buf[headerLength]
			icmpCode := buf[headerLength+1]

			log.Printf("ICMP type=%d code=%d", icmpType, icmpCode)
		}
	}
}

func validatePacket(buf []byte) (version, headerLength, protocol, totalLength int, err error) {
	if len(buf) < 20 {
		return 0, 0, 0, 0, fmt.Errorf("packet too short: %d bytes", len(buf))
	}

	version = int(buf[0] >> 4)
	if version != 4 {
		return 0, 0, 0, 0, fmt.Errorf("ignoring IP version %d", version)
	}

	headerLength = int(buf[0]&0x0f) * 4
	if headerLength < 20 {
		return 0, 0, 0, 0, fmt.Errorf("invalid IPv4 header length: %d bytes", headerLength)
	}
	if headerLength > len(buf) {
		return 0, 0, 0, 0, fmt.Errorf("truncated IPv4 header: need %d bytes, got %d", headerLength, len(buf))
	}

	if checksum := internetChecksum(buf[:headerLength]); checksum != 0 {
		return 0, 0, 0, 0, fmt.Errorf(
			"invalid IPv4 header checksum: %#04x",
			checksum,
		)
	}

	protocol = int(buf[9])

	totalLength = int(binary.BigEndian.Uint16(buf[2:4]))

	if totalLength < headerLength {
		return 0, 0, 0, 0, fmt.Errorf("invalid IPv4 total length: %d, header length: %d", totalLength, headerLength)
	}

	if totalLength > len(buf) {
		return 0, 0, 0, 0, fmt.Errorf("truncated IPv4 packet: expected %d bytes, got %d", totalLength, len(buf))
	}

	return version, headerLength, protocol, totalLength, nil
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
