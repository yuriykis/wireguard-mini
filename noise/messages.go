package noise

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	HandshakeInitiationSize = 148

	handshakeInitiationType byte = 1

	senderIndexOffset        = 4
	ephemeralOffset          = 8
	encryptedStaticOffset    = 40
	encryptedTimestampOffset = 88
	mac1Offset               = 116
	mac2Offset               = 132
)

// HandshakeInitiation contains the fields carried by WireGuard's first
// handshake message. The message type and the three reserved zero bytes are
// part of the wire format, so callers do not have to set them.
type HandshakeInitiation struct {
	SenderIndex          uint32
	UnencryptedEphemeral [32]byte
	EncryptedStatic      [48]byte
	EncryptedTimestamp   [28]byte
	MAC1                 [16]byte
	MAC2                 [16]byte
}

// MarshalBinary encodes a handshake initiation in WireGuard's 148-byte wire
// format.
func (m HandshakeInitiation) MarshalBinary() []byte {
	data := make([]byte, HandshakeInitiationSize)
	data[0] = handshakeInitiationType
	binary.LittleEndian.PutUint32(data[senderIndexOffset:ephemeralOffset], m.SenderIndex)
	copy(data[ephemeralOffset:encryptedStaticOffset], m.UnencryptedEphemeral[:])
	copy(data[encryptedStaticOffset:encryptedTimestampOffset], m.EncryptedStatic[:])
	copy(data[encryptedTimestampOffset:mac1Offset], m.EncryptedTimestamp[:])
	copy(data[mac1Offset:mac2Offset], m.MAC1[:])
	copy(data[mac2Offset:], m.MAC2[:])
	return data
}

// ParseHandshakeInitiation decodes a WireGuard handshake initiation. It
// accepts only the exact message length, type, and reserved-zero bytes defined
// by the protocol.
func ParseHandshakeInitiation(data []byte) (HandshakeInitiation, error) {
	var message HandshakeInitiation

	if len(data) != HandshakeInitiationSize {
		return message, fmt.Errorf("invalid handshake initiation length: got %d, want %d", len(data), HandshakeInitiationSize)
	}
	if data[0] != handshakeInitiationType {
		return message, fmt.Errorf("invalid handshake initiation type: got %d, want %d", data[0], handshakeInitiationType)
	}
	if data[1] != 0 || data[2] != 0 || data[3] != 0 {
		return message, errors.New("handshake initiation reserved bytes must be zero")
	}

	message.SenderIndex = binary.LittleEndian.Uint32(data[senderIndexOffset:ephemeralOffset])
	copy(message.UnencryptedEphemeral[:], data[ephemeralOffset:encryptedStaticOffset])
	copy(message.EncryptedStatic[:], data[encryptedStaticOffset:encryptedTimestampOffset])
	copy(message.EncryptedTimestamp[:], data[encryptedTimestampOffset:mac1Offset])
	copy(message.MAC1[:], data[mac1Offset:mac2Offset])
	copy(message.MAC2[:], data[mac2Offset:])
	return message, nil
}
