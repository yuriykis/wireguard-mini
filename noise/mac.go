package noise

import (
	"crypto/hmac"
	"errors"

	"golang.org/x/crypto/blake2s"
)

const labelMAC1 = "mac1----"

func deriveMAC1Key(recipientPublicKey PublicKey) [HashSize]byte {
	input := make([]byte, 0, len(labelMAC1)+len(recipientPublicKey))
	input = append(input, labelMAC1...)
	input = append(input, recipientPublicKey[:]...)
	return blake2s.Sum256(input)
}

func calculateMAC1(mac1Key [HashSize]byte, data []byte) [16]byte {
	mac, err := blake2s.New128(mac1Key[:])
	if err != nil {
		panic("create keyed BLAKE2s-128: " + err.Error())
	}
	_, _ = mac.Write(data)

	var result [16]byte
	copy(result[:], mac.Sum(nil))
	return result
}

func setInitiationMAC1(message *HandshakeInitiation, responderPublicKey PublicKey) {
	data := message.MarshalBinary()
	mac1Key := deriveMAC1Key(responderPublicKey)
	message.MAC1 = calculateMAC1(mac1Key, data[:mac1Offset])
}

// The comparison is constant time: a MAC compared byte by byte can be guessed
// one byte at a time by timing the answers.
func verifyInitiationMAC1(data []byte, responderPublicKey PublicKey) error {
	mac1Key := deriveMAC1Key(responderPublicKey)
	expected := calculateMAC1(mac1Key, data[:mac1Offset])

	if !hmac.Equal(expected[:], data[mac1Offset:mac2Offset]) {
		return errors.New("handshake initiation MAC1 mismatch")
	}
	return nil
}

func verifyResponseMAC1(data []byte, initiatorStaticPublic PublicKey) error {
	mac1Key := deriveMAC1Key(initiatorStaticPublic)
	expected := calculateMAC1(mac1Key, data[:responseMAC1Offset])

	if !hmac.Equal(expected[:], data[responseMAC1Offset:responseMAC2Offset]) {
		return errors.New("handshake response MAC1 mismatch")
	}
	return nil
}

// Cookies are out of scope, so MAC2 is always zero.
func setInitiationMAC2(message *HandshakeInitiation) {
	message.MAC2 = [16]byte{}
}

// The MAC1 key is the recipient's static public key, here the initiator's.
func setResponseMAC1(message *HandshakeResponse, initiatorStaticPublic PublicKey) {
	data := message.MarshalBinary()
	mac1Key := deriveMAC1Key(initiatorStaticPublic)
	message.MAC1 = calculateMAC1(mac1Key, data[:responseMAC1Offset])
}

// Cookies are out of scope, so MAC2 is always zero.
func setResponseMAC2(message *HandshakeResponse) {
	message.MAC2 = [16]byte{}
}
