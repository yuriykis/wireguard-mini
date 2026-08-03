package main

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInternetChecksum(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want uint16
	}{
		{name: "empty", data: nil, want: 0xffff},
		{name: "even length", data: []byte{0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7}, want: 0x220d},
		{name: "odd length", data: []byte{0x00, 0x01, 0xf2}, want: 0x0dfe},
		{name: "valid ICMP request", data: []byte{8, 0, 0xfd, 0xf0, 0x12, 0x34, 0, 1, 't', 'e', 's', 't'}, want: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, internetChecksum(tt.data))
		})
	}
}

func TestParseICMPEcho(t *testing.T) {
	packet := []byte{8, 0, 0xfd, 0xf0, 0x12, 0x34, 0, 1, 't', 'e', 's', 't'}

	echo, err := parseICMPEcho(packet)
	require.NoError(t, err)
	require.Equal(t, uint8(icmpEchoRequestType), echo.icmpType)
	require.Equal(t, uint8(icmpEchoCode), echo.code)
	require.Equal(t, uint16(0x1234), echo.identifier)
	require.Equal(t, uint16(1), echo.sequence)
	require.Equal(t, []byte("test"), echo.data)
}

func TestParseICMPEchoRejectsInvalidPackets(t *testing.T) {
	tests := []struct {
		name    string
		packet  []byte
		wantErr string
	}{
		{name: "too short", packet: make([]byte, icmpEchoHeaderLength-1), wantErr: "too short"},
		{name: "invalid checksum", packet: []byte{8, 0, 0, 0, 0x12, 0x34, 0, 1}, wantErr: "invalid ICMP checksum"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseICMPEcho(tt.packet)
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestParseIPv4Packet(t *testing.T) {
	payload := []byte{8, 0, 0xfd, 0xf0, 0x12, 0x34, 0, 1, 't', 'e', 's', 't'}
	packet := validIPv4Packet(payload)

	parsed, err := parseIPv4Packet(packet)
	require.NoError(t, err)
	require.Equal(t, ipv4MinimumHeaderLength, parsed.headerLength)
	require.Equal(t, len(packet), parsed.totalLength)
	require.Equal(t, uint8(protocolICMP), parsed.protocol)
	require.Equal(t, netip.MustParseAddr("10.0.0.1"), parsed.source)
	require.Equal(t, netip.MustParseAddr("10.0.0.2"), parsed.destination)
	require.Equal(t, payload, parsed.payload)
}

func TestParseIPv4PacketRejectsInvalidPackets(t *testing.T) {
	valid := validIPv4Packet(nil)

	tests := []struct {
		name    string
		packet  []byte
		wantErr string
	}{
		{name: "too short", packet: make([]byte, ipv4MinimumHeaderLength-1), wantErr: "packet too short"},
		{name: "wrong version", packet: withByte(valid, 0, 0x65), wantErr: "IP version 6"},
		{name: "header too short", packet: withByte(valid, 0, 0x44), wantErr: "invalid IPv4 header length"},
		{name: "truncated header", packet: withByte(valid, 0, 0x4f), wantErr: "truncated IPv4 header"},
		{name: "invalid checksum", packet: withByte(valid, 8, 63), wantErr: "invalid IPv4 header checksum"},
		{name: "total length below header", packet: withUint16AndChecksum(valid, 2, 19), wantErr: "invalid IPv4 total length"},
		{name: "truncated packet", packet: withUint16AndChecksum(valid, 2, 21), wantErr: "truncated IPv4 packet"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseIPv4Packet(tt.packet)
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestBuildICMPEchoReply(t *testing.T) {
	request := []byte{
		8, 0, 0xfd, 0xf0, // type, code, checksum
		0x12, 0x34, 0, 1, // identifier, sequence
		't', 'e', 's', 't',
	}
	originalRequest := append([]byte(nil), request...)

	reply, err := buildICMPEchoReply(request)
	require.NoError(t, err)

	want := []byte{
		0, 0, 0x05, 0xf1, // type, code, checksum
		0x12, 0x34, 0, 1, // identifier, sequence
		't', 'e', 's', 't',
	}
	require.Equal(t, want, reply)
	require.Equal(t, originalRequest, request)
	require.Zero(t, internetChecksum(reply))
}

func TestBuildIPv4Reply(t *testing.T) {
	requestPayload := []byte{8, 0, 0xfd, 0xf0, 0x12, 0x34, 0, 1, 't', 'e', 's', 't'}
	request := validIPv4Packet(requestPayload)
	originalRequest := append([]byte(nil), request...)
	replyPayload := []byte{0, 0, 0x05, 0xf1, 0x12, 0x34, 0, 1, 't', 'e', 's', 't'}

	reply, err := buildIPv4Reply(request, replyPayload)
	require.NoError(t, err)
	require.Equal(t, originalRequest, request)

	parsed, err := parseIPv4Packet(reply)
	require.NoError(t, err)
	require.Equal(t, netip.MustParseAddr("10.0.0.2"), parsed.source)
	require.Equal(t, netip.MustParseAddr("10.0.0.1"), parsed.destination)
	require.Equal(t, replyPayload, parsed.payload)
	require.Equal(t, len(reply), parsed.totalLength)
	require.Zero(t, internetChecksum(reply[:parsed.headerLength]))
}

func TestBuildIPv4ReplyPreservesHeaderOptions(t *testing.T) {
	request := validIPv4PacketWithOptions([]byte{1, 2, 3, 4}, []byte("request"))
	replyPayload := []byte("reply")

	reply, err := buildIPv4Reply(request, replyPayload)
	require.NoError(t, err)

	parsed, err := parseIPv4Packet(reply)
	require.NoError(t, err)
	require.Equal(t, 24, parsed.headerLength)
	require.Equal(t, request[20:24], reply[20:24])
	require.Equal(t, replyPayload, parsed.payload)
}

func TestBuildIPv4ReplyRejectsOversizedPacket(t *testing.T) {
	request := validIPv4Packet(nil)

	_, err := buildIPv4Reply(request, make([]byte, 0x10000))
	require.ErrorContains(t, err, "IPv4 reply too large")
}

func validIPv4Packet(payload []byte) []byte {
	return validIPv4PacketWithOptions(nil, payload)
}

func validIPv4PacketWithOptions(options, payload []byte) []byte {
	headerLength := ipv4MinimumHeaderLength + len(options)
	packet := make([]byte, headerLength+len(payload))
	packet[0] = byte(ipv4Version<<4 | headerLength/4)
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8] = 64
	packet[9] = protocolICMP
	copy(packet[12:16], []byte{10, 0, 0, 1})
	copy(packet[16:20], []byte{10, 0, 0, 2})
	copy(packet[ipv4MinimumHeaderLength:headerLength], options)
	copy(packet[headerLength:], payload)
	binary.BigEndian.PutUint16(packet[10:12], internetChecksum(packet[:headerLength]))
	return packet
}

func withByte(packet []byte, index int, value byte) []byte {
	result := append([]byte(nil), packet...)
	result[index] = value
	return result
}

func withUint16AndChecksum(packet []byte, index int, value uint16) []byte {
	result := append([]byte(nil), packet...)
	binary.BigEndian.PutUint16(result[index:index+2], value)
	binary.BigEndian.PutUint16(result[10:12], 0)
	binary.BigEndian.PutUint16(result[10:12], internetChecksum(result[:ipv4MinimumHeaderLength]))
	return result
}
