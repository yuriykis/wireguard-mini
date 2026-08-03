package main

import (
	"encoding/binary"
	"fmt"
	"io"
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
	icmpEchoHeaderLength    = 8
	icmpEchoReplyType       = 0
	icmpEchoRequestType     = 8
	icmpEchoCode            = 0
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

type icmpEcho struct {
	icmpType   uint8
	code       uint8
	identifier uint16
	sequence   uint16
	data       []byte
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
			echo, err := parseICMPEcho(packet.payload)
			if err != nil {
				log.Printf("invalid ICMP echo packet: %v", err)
				continue
			}
			if echo.icmpType != icmpEchoRequestType || echo.code != icmpEchoCode {
				log.Printf("ignoring ICMP type=%d code=%d", echo.icmpType, echo.code)
				continue
			}

			log.Printf(
				"ICMP type=%d code=%d identifier=%d sequence=%d dataLength=%d",
				echo.icmpType,
				echo.code,
				echo.identifier,
				echo.sequence,
				len(echo.data),
			)

			icmpReply, err := buildICMPEchoReply(packet.payload)
			if err != nil {
				log.Printf("could not build ICMP echo reply: %v", err)
				continue
			}

			ipv4Reply, err := buildIPv4Reply(buf[:n], icmpReply)
			if err != nil {
				log.Printf("could not build IPv4 reply: %v", err)
				continue
			}

			written, err := file.Write(ipv4Reply)
			if err != nil {
				log.Printf("could not write IPv4 reply to TUN: %v", err)
				continue
			}
			if written != len(ipv4Reply) {
				log.Printf("could not write IPv4 reply to TUN: %v", io.ErrShortWrite)
				continue
			}
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

func parseICMPEcho(data []byte) (icmpEcho, error) {
	if len(data) < icmpEchoHeaderLength {
		return icmpEcho{}, fmt.Errorf("ICMP echo packet too short: %d bytes", len(data))
	}

	if checksum := internetChecksum(data); checksum != 0 {
		return icmpEcho{}, fmt.Errorf("invalid ICMP checksum: %#04x", checksum)
	}

	return icmpEcho{
		icmpType:   data[0],
		code:       data[1],
		identifier: binary.BigEndian.Uint16(data[4:6]),
		sequence:   binary.BigEndian.Uint16(data[6:8]),
		data:       data[icmpEchoHeaderLength:],
	}, nil
}

func buildICMPEchoReply(request []byte) ([]byte, error) {
	echo, err := parseICMPEcho(request)
	if err != nil {
		return nil, err
	}
	if echo.icmpType != icmpEchoRequestType || echo.code != icmpEchoCode {
		return nil, fmt.Errorf("not an ICMP echo request: type=%d code=%d", echo.icmpType, echo.code)
	}

	reply := append([]byte(nil), request...)
	reply[0] = icmpEchoReplyType
	// The checksum field must be zero while calculating the ICMP checksum.
	binary.BigEndian.PutUint16(reply[2:4], 0)
	binary.BigEndian.PutUint16(reply[2:4], internetChecksum(reply))

	return reply, nil
}

func buildIPv4Reply(request []byte, payload []byte) ([]byte, error) {
	packet, err := parseIPv4Packet(request)
	if err != nil {
		return nil, err
	}

	totalLength := packet.headerLength + len(payload)
	if totalLength > 0xffff {
		return nil, fmt.Errorf("IPv4 reply too large: %d bytes", totalLength)
	}

	reply := make([]byte, totalLength)
	// Preserve the original IPv4 header, including any options after the first 20 bytes.
	copy(reply[:packet.headerLength], request[:packet.headerLength])
	copy(reply[packet.headerLength:], payload)

	// Swap the 4-byte IPv4 source (12:16) and destination (16:20) addresses.
	copy(reply[12:16], request[16:20])
	copy(reply[16:20], request[12:16])

	binary.BigEndian.PutUint16(reply[2:4], uint16(totalLength))
	// The checksum field must be zero while calculating the IPv4 header checksum.
	binary.BigEndian.PutUint16(reply[10:12], 0)
	binary.BigEndian.PutUint16(reply[10:12], internetChecksum(reply[:packet.headerLength]))

	return reply, nil
}

func internetChecksum(data []byte) uint16 {
	var sum uint32

	for len(data) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
	}

	if len(data) == 1 {
		// The final odd byte is the high-order byte of a 16-bit word.
		sum += uint32(data[0]) << 8
	}

	// Add every carry back into the low 16 bits (one's-complement addition).
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}

	return ^uint16(sum)
}
