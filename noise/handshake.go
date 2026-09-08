package noise

import (
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

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
