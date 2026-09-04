package noise

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	HandshakeInitiationSize = 148
	HandshakeResponseSize   = 92

	handshakeInitiationType byte = 1
	handshakeResponseType   byte = 2

	senderIndexOffset        = 4
	ephemeralOffset          = 8
	encryptedStaticOffset    = 40
	encryptedTimestampOffset = 88
	mac1Offset               = 116
	mac2Offset               = 132

	responseSenderIndexOffset      = 4
	responseReceiverIndexOffset    = 8
	responseEphemeralOffset        = 12
	responseEncryptedNothingOffset = 44
	responseMAC1Offset             = 60
	responseMAC2Offset             = 76
)

// HandshakeInitiation contains the fields carried by WireGuard's first handshake message.
type HandshakeInitiation struct {
	SenderIndex          uint32
	UnencryptedEphemeral [32]byte
	EncryptedStatic      [48]byte
	EncryptedTimestamp   [28]byte
	MAC1                 [16]byte
	MAC2                 [16]byte
}

// HandshakeResponse contains the fields carried by WireGuard's second handshake message.
type HandshakeResponse struct {
	SenderIndex          uint32
	ReceiverIndex        uint32
	UnencryptedEphemeral [32]byte
	EncryptedNothing     [16]byte
	MAC1                 [16]byte
	MAC2                 [16]byte
}

// MarshalBinary encodes a handshake response in WireGuard's 92-byte wire format.
func (m HandshakeResponse) MarshalBinary() []byte {
	data := make([]byte, HandshakeResponseSize)
	data[0] = handshakeResponseType
	binary.LittleEndian.PutUint32(data[responseSenderIndexOffset:responseReceiverIndexOffset], m.SenderIndex)
	binary.LittleEndian.PutUint32(data[responseReceiverIndexOffset:responseEphemeralOffset], m.ReceiverIndex)
	copy(data[responseEphemeralOffset:responseEncryptedNothingOffset], m.UnencryptedEphemeral[:])
	copy(data[responseEncryptedNothingOffset:responseMAC1Offset], m.EncryptedNothing[:])
	copy(data[responseMAC1Offset:responseMAC2Offset], m.MAC1[:])
	copy(data[responseMAC2Offset:], m.MAC2[:])
	return data
}

// ParseHandshakeResponse decodes a WireGuard handshake response.
func ParseHandshakeResponse(data []byte) (HandshakeResponse, error) {
	var message HandshakeResponse

	if len(data) != HandshakeResponseSize {
		return message, fmt.Errorf("invalid handshake response length: got %d, want %d", len(data), HandshakeResponseSize)
	}
	if data[0] != handshakeResponseType {
		return message, fmt.Errorf("invalid handshake response type: got %d, want %d", data[0], handshakeResponseType)
	}
	if data[1] != 0 || data[2] != 0 || data[3] != 0 {
		return message, errors.New("handshake response reserved bytes must be zero")
	}

	message.SenderIndex = binary.LittleEndian.Uint32(data[responseSenderIndexOffset:responseReceiverIndexOffset])
	message.ReceiverIndex = binary.LittleEndian.Uint32(data[responseReceiverIndexOffset:responseEphemeralOffset])
	copy(message.UnencryptedEphemeral[:], data[responseEphemeralOffset:responseEncryptedNothingOffset])
	copy(message.EncryptedNothing[:], data[responseEncryptedNothingOffset:responseMAC1Offset])
	copy(message.MAC1[:], data[responseMAC1Offset:responseMAC2Offset])
	copy(message.MAC2[:], data[responseMAC2Offset:])
	return message, nil
}

// MarshalBinary encodes a handshake initiation in WireGuard's 148-byte wire format.
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

// ParseHandshakeInitiation decodes a WireGuard handshake initiation.
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
