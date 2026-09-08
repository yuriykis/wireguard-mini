package noise

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// CreateInitiation builds a handshake initiation, the initiator's ephemeral
// private key, and the state it leaves behind.
func CreateInitiation(
	initiatorStaticPrivate PrivateKey,
	responderStaticPublic PublicKey,
) (HandshakeInitiation, PrivateKey, HandshakeState, error) {
	initiatorStaticPublic, err := initiatorStaticPrivate.PublicKey()
	if err != nil {
		return HandshakeInitiation{}, PrivateKey{}, HandshakeState{}, err
	}

	state := NewHandshakeState(responderStaticPublic)
	var message HandshakeInitiation

	message.SenderIndex, err = generateSenderIndex()
	if err != nil {
		return HandshakeInitiation{}, PrivateKey{}, HandshakeState{}, err
	}

	ephemeralPrivate, err := state.setInitiationEphemeral(&message)
	if err != nil {
		return HandshakeInitiation{}, PrivateKey{}, HandshakeState{}, err
	}

	staticEncryptionKey, err := state.deriveInitiationStaticEncryptionKey(
		ephemeralPrivate,
		responderStaticPublic,
	)
	if err != nil {
		return HandshakeInitiation{}, PrivateKey{}, HandshakeState{}, err
	}
	if err := state.encryptInitiationStatic(
		&message,
		staticEncryptionKey,
		initiatorStaticPublic,
	); err != nil {
		return HandshakeInitiation{}, PrivateKey{}, HandshakeState{}, err
	}

	timestampEncryptionKey, err := state.deriveInitiationTimestampEncryptionKey(
		initiatorStaticPrivate,
		responderStaticPublic,
	)
	if err != nil {
		return HandshakeInitiation{}, PrivateKey{}, HandshakeState{}, err
	}
	if err := state.encryptInitiationTimestamp(
		&message,
		timestampEncryptionKey,
		newTAI64NTimestamp(time.Now()),
	); err != nil {
		return HandshakeInitiation{}, PrivateKey{}, HandshakeState{}, err
	}

	// The authenticators are not part of the Noise transcript.
	setInitiationMAC1(&message, responderStaticPublic)
	setInitiationMAC2(&message)
	return message, ephemeralPrivate, state, nil
}

func (state *HandshakeState) setInitiationEphemeral(message *HandshakeInitiation) (PrivateKey, error) {
	ephemeralPrivate, err := GeneratePrivateKey()
	if err != nil {
		return PrivateKey{}, err
	}

	ephemeralPublic, err := ephemeralPrivate.PublicKey()
	if err != nil {
		return PrivateKey{}, err
	}

	copy(message.UnencryptedEphemeral[:], ephemeralPublic[:])
	state.mixHash(message.UnencryptedEphemeral[:])
	state.mixKey(message.UnencryptedEphemeral[:])
	return ephemeralPrivate, nil
}

func (state *HandshakeState) consumeInitiationEphemeral(message HandshakeInitiation) {
	state.mixHash(message.UnencryptedEphemeral[:])
	state.mixKey(message.UnencryptedEphemeral[:])
}

func (state *HandshakeState) deriveInitiationStaticEncryptionKey(
	ephemeralPrivate PrivateKey,
	responderStaticPublic PublicKey,
) ([HashSize]byte, error) {
	sharedSecret, err := ephemeralPrivate.SharedSecret(responderStaticPublic)
	if err != nil {
		return [HashSize]byte{}, err
	}

	return state.mixKeyAndGetEncryptionKey(sharedSecret[:]), nil
}

func (state *HandshakeState) consumeInitiationStaticDecryptionKey(
	responderStaticPrivate PrivateKey,
	message HandshakeInitiation,
) ([HashSize]byte, error) {
	var initiatorEphemeralPublic PublicKey
	copy(initiatorEphemeralPublic[:], message.UnencryptedEphemeral[:])

	sharedSecret, err := responderStaticPrivate.SharedSecret(initiatorEphemeralPublic)
	if err != nil {
		return [HashSize]byte{}, err
	}

	return state.mixKeyAndGetEncryptionKey(sharedSecret[:]), nil
}

func (state *HandshakeState) encryptInitiationStatic(
	message *HandshakeInitiation,
	encryptionKey [HashSize]byte,
	initiatorStaticPublic PublicKey,
) error {
	aead, err := chacha20poly1305.New(encryptionKey[:])
	if err != nil {
		return err
	}

	var nonce [chacha20poly1305.NonceSize]byte
	encryptedStatic := aead.Seal(
		nil,
		nonce[:],
		initiatorStaticPublic[:],
		state.Hash[:],
	)
	copy(message.EncryptedStatic[:], encryptedStatic)
	state.mixHash(message.EncryptedStatic[:])
	return nil
}

func (state *HandshakeState) decryptInitiationStatic(
	message HandshakeInitiation,
	decryptionKey [HashSize]byte,
) (PublicKey, error) {
	aead, err := chacha20poly1305.New(decryptionKey[:])
	if err != nil {
		return PublicKey{}, err
	}

	var nonce [chacha20poly1305.NonceSize]byte
	plaintext, err := aead.Open(
		nil,
		nonce[:],
		message.EncryptedStatic[:],
		state.Hash[:],
	)
	if err != nil {
		return PublicKey{}, fmt.Errorf("decrypt handshake initiation static key: %w", err)
	}

	var initiatorStaticPublic PublicKey
	copy(initiatorStaticPublic[:], plaintext)
	state.mixHash(message.EncryptedStatic[:])
	return initiatorStaticPublic, nil
}

func (state *HandshakeState) deriveInitiationTimestampEncryptionKey(
	initiatorStaticPrivate PrivateKey,
	responderStaticPublic PublicKey,
) ([HashSize]byte, error) {
	sharedSecret, err := initiatorStaticPrivate.SharedSecret(responderStaticPublic)
	if err != nil {
		return [HashSize]byte{}, err
	}

	return state.mixKeyAndGetEncryptionKey(sharedSecret[:]), nil
}

func (state *HandshakeState) consumeInitiationTimestampDecryptionKey(
	responderStaticPrivate PrivateKey,
	initiatorStaticPublic PublicKey,
) ([HashSize]byte, error) {
	sharedSecret, err := responderStaticPrivate.SharedSecret(initiatorStaticPublic)
	if err != nil {
		return [HashSize]byte{}, err
	}

	return state.mixKeyAndGetEncryptionKey(sharedSecret[:]), nil
}

func (state *HandshakeState) encryptInitiationTimestamp(
	message *HandshakeInitiation,
	encryptionKey [HashSize]byte,
	timestamp tai64nTimestamp,
) error {
	aead, err := chacha20poly1305.New(encryptionKey[:])
	if err != nil {
		return err
	}

	var nonce [chacha20poly1305.NonceSize]byte
	encryptedTimestamp := aead.Seal(
		nil,
		nonce[:],
		timestamp[:],
		state.Hash[:],
	)
	copy(message.EncryptedTimestamp[:], encryptedTimestamp)
	state.mixHash(message.EncryptedTimestamp[:])
	return nil
}

func (state *HandshakeState) decryptInitiationTimestamp(
	message HandshakeInitiation,
	decryptionKey [HashSize]byte,
) (tai64nTimestamp, error) {
	aead, err := chacha20poly1305.New(decryptionKey[:])
	if err != nil {
		return tai64nTimestamp{}, err
	}

	var nonce [chacha20poly1305.NonceSize]byte
	plaintext, err := aead.Open(
		nil,
		nonce[:],
		message.EncryptedTimestamp[:],
		state.Hash[:],
	)
	if err != nil {
		return tai64nTimestamp{}, fmt.Errorf("decrypt handshake initiation timestamp: %w", err)
	}

	var timestamp tai64nTimestamp
	copy(timestamp[:], plaintext)
	state.mixHash(message.EncryptedTimestamp[:])
	return timestamp, nil
}

func (state *HandshakeState) encryptResponseNothing(
	message *HandshakeResponse,
	encryptionKey [HashSize]byte,
) error {
	aead, err := chacha20poly1305.New(encryptionKey[:])
	if err != nil {
		return err
	}

	var nonce [chacha20poly1305.NonceSize]byte
	encryptedNothing := aead.Seal(nil, nonce[:], nil, state.Hash[:])
	copy(message.EncryptedNothing[:], encryptedNothing)
	state.mixHash(message.EncryptedNothing[:])
	return nil
}

func (state *HandshakeState) decryptResponseNothing(
	message HandshakeResponse,
	decryptionKey [HashSize]byte,
) error {
	aead, err := chacha20poly1305.New(decryptionKey[:])
	if err != nil {
		return err
	}

	var nonce [chacha20poly1305.NonceSize]byte
	if _, err := aead.Open(nil, nonce[:], message.EncryptedNothing[:], state.Hash[:]); err != nil {
		return fmt.Errorf("decrypt handshake response nothing: %w", err)
	}

	state.mixHash(message.EncryptedNothing[:])
	return nil
}
func generateSenderIndex() (uint32, error) {
	var indexBytes [4]byte
	if _, err := rand.Read(indexBytes[:]); err != nil {
		return 0, fmt.Errorf("generate sender index: %w", err)
	}

	return binary.LittleEndian.Uint32(indexBytes[:]), nil
}

// ConsumeInitiation processes a handshake initiation and returns the initiator's
// static public key, its claimed timestamp, and the state it leaves behind.
func ConsumeInitiation(
	responderStaticPrivate PrivateKey,
	data []byte,
) (HandshakeInitiation, PublicKey, tai64nTimestamp, HandshakeState, error) {
	message, err := ParseHandshakeInitiation(data)
	if err != nil {
		return HandshakeInitiation{}, PublicKey{}, tai64nTimestamp{}, HandshakeState{}, err
	}

	responderStaticPublic, err := responderStaticPrivate.PublicKey()
	if err != nil {
		return HandshakeInitiation{}, PublicKey{}, tai64nTimestamp{}, HandshakeState{}, err
	}
	if err := verifyInitiationMAC1(data, responderStaticPublic); err != nil {
		return HandshakeInitiation{}, PublicKey{}, tai64nTimestamp{}, HandshakeState{}, err
	}

	state := NewHandshakeState(responderStaticPublic)
	state.consumeInitiationEphemeral(message)

	staticDecryptionKey, err := state.consumeInitiationStaticDecryptionKey(responderStaticPrivate, message)
	if err != nil {
		return HandshakeInitiation{}, PublicKey{}, tai64nTimestamp{}, HandshakeState{}, err
	}

	initiatorStaticPublic, err := state.decryptInitiationStatic(message, staticDecryptionKey)
	if err != nil {
		return HandshakeInitiation{}, PublicKey{}, tai64nTimestamp{}, HandshakeState{}, err
	}

	timestampDecryptionKey, err := state.consumeInitiationTimestampDecryptionKey(
		responderStaticPrivate,
		initiatorStaticPublic,
	)
	if err != nil {
		return HandshakeInitiation{}, PublicKey{}, tai64nTimestamp{}, HandshakeState{}, err
	}

	// The timestamp is returned rather than checked: replay defence needs a
	// peer table, which does not exist yet.
	timestamp, err := state.decryptInitiationTimestamp(message, timestampDecryptionKey)
	if err != nil {
		return HandshakeInitiation{}, PublicKey{}, tai64nTimestamp{}, HandshakeState{}, err
	}

	return message, initiatorStaticPublic, timestamp, state, nil
}

// CreateResponse builds a handshake response and the state it leaves behind,
// continuing the transcript ConsumeInitiation produced.
func CreateResponse(
	initiatorStaticPublic PublicKey,
	initiation HandshakeInitiation,
	state HandshakeState,
) (HandshakeResponse, HandshakeState, error) {
	var message HandshakeResponse

	senderIndex, err := generateSenderIndex()
	if err != nil {
		return HandshakeResponse{}, HandshakeState{}, err
	}
	message.SenderIndex = senderIndex
	message.ReceiverIndex = initiation.SenderIndex

	ephemeralPrivate, err := state.setResponseEphemeral(&message)
	if err != nil {
		return HandshakeResponse{}, HandshakeState{}, err
	}

	if err := state.mixResponseEphemeralSharedSecret(
		ephemeralPrivate,
		PublicKey(initiation.UnencryptedEphemeral),
	); err != nil {
		return HandshakeResponse{}, HandshakeState{}, err
	}

	if err := state.mixResponseStaticSharedSecret(
		ephemeralPrivate,
		initiatorStaticPublic,
	); err != nil {
		return HandshakeResponse{}, HandshakeState{}, err
	}

	// An unconfigured preshared key is all-zero.
	var presharedKey [PresharedKeySize]byte
	encryptionKey := state.mixKeyHashAndGetEncryptionKey(presharedKey[:])

	if err := state.encryptResponseNothing(&message, encryptionKey); err != nil {
		return HandshakeResponse{}, HandshakeState{}, err
	}

	// The authenticators are not part of the Noise transcript.
	setResponseMAC1(&message, initiatorStaticPublic)
	setResponseMAC2(&message)
	return message, state, nil
}

func (state *HandshakeState) mixResponseEphemeralSharedSecret(
	responderEphemeralPrivate PrivateKey,
	initiatorEphemeralPublic PublicKey,
) error {
	sharedSecret, err := responderEphemeralPrivate.SharedSecret(initiatorEphemeralPublic)
	if err != nil {
		return err
	}

	state.mixKey(sharedSecret[:])
	return nil
}

func (state *HandshakeState) mixResponseStaticSharedSecret(
	responderEphemeralPrivate PrivateKey,
	initiatorStaticPublic PublicKey,
) error {
	sharedSecret, err := responderEphemeralPrivate.SharedSecret(initiatorStaticPublic)
	if err != nil {
		return err
	}

	state.mixKey(sharedSecret[:])
	return nil
}

func (state *HandshakeState) setResponseEphemeral(message *HandshakeResponse) (PrivateKey, error) {
	ephemeralPrivate, err := GeneratePrivateKey()
	if err != nil {
		return PrivateKey{}, err
	}

	ephemeralPublic, err := ephemeralPrivate.PublicKey()
	if err != nil {
		return PrivateKey{}, err
	}

	copy(message.UnencryptedEphemeral[:], ephemeralPublic[:])
	state.mixHash(message.UnencryptedEphemeral[:])
	state.mixKey(message.UnencryptedEphemeral[:])
	return ephemeralPrivate, nil
}

func (state *HandshakeState) consumeResponseEphemeral(message HandshakeResponse) {
	state.mixHash(message.UnencryptedEphemeral[:])
	state.mixKey(message.UnencryptedEphemeral[:])
}

// ConsumeResponse processes a handshake response and returns it together with
// the state it leaves behind. A failure is answered with silence.
func ConsumeResponse(
	initiatorStaticPrivate PrivateKey,
	initiatorEphemeralPrivate PrivateKey,
	data []byte,
	state HandshakeState,
) (HandshakeResponse, HandshakeState, error) {
	message, err := ParseHandshakeResponse(data)
	if err != nil {
		return HandshakeResponse{}, HandshakeState{}, err
	}

	initiatorStaticPublic, err := initiatorStaticPrivate.PublicKey()
	if err != nil {
		return HandshakeResponse{}, HandshakeState{}, err
	}
	if err := verifyResponseMAC1(data, initiatorStaticPublic); err != nil {
		return HandshakeResponse{}, HandshakeState{}, err
	}

	state.consumeResponseEphemeral(message)

	ephemeralSharedSecret, err := initiatorEphemeralPrivate.SharedSecret(
		PublicKey(message.UnencryptedEphemeral),
	)
	if err != nil {
		return HandshakeResponse{}, HandshakeState{}, err
	}
	state.mixKey(ephemeralSharedSecret[:])

	staticSharedSecret, err := initiatorStaticPrivate.SharedSecret(
		PublicKey(message.UnencryptedEphemeral),
	)
	if err != nil {
		return HandshakeResponse{}, HandshakeState{}, err
	}
	state.mixKey(staticSharedSecret[:])

	// An unconfigured preshared key is all-zero.
	var presharedKey [PresharedKeySize]byte
	decryptionKey := state.mixKeyHashAndGetEncryptionKey(presharedKey[:])

	if err := state.decryptResponseNothing(message, decryptionKey); err != nil {
		return HandshakeResponse{}, HandshakeState{}, err
	}

	return message, state, nil
}
