package noise

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"time"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	HashSize         = 32
	ChainingKeySize  = 32
	PresharedKeySize = 32

	noiseConstruction   = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
	wireGuardIdentifier = "WireGuard v1 zx2c4 Jason@zx2c4.com"
	labelMAC1           = "mac1----"
)

// HandshakeState holds the two evolving 32-byte values used by Noise.
type HandshakeState struct {
	Hash        [HashSize]byte
	ChainingKey [ChainingKeySize]byte
}

// NewHandshakeState initializes the Noise state bound to the responder's identity.
func NewHandshakeState(responderPublicKey PublicKey) HandshakeState {
	chainingKey := blake2s.Sum256([]byte(noiseConstruction))

	hashInput := make([]byte, 0, len(chainingKey)+len(wireGuardIdentifier))
	hashInput = append(hashInput, chainingKey[:]...)
	hashInput = append(hashInput, wireGuardIdentifier...)
	state := HandshakeState{
		Hash:        blake2s.Sum256(hashInput),
		ChainingKey: chainingKey,
	}
	state.mixHash(responderPublicKey[:])
	return state
}

// CreateInitiation builds a handshake initiation and the state it leaves behind.
func CreateInitiation(
	initiatorStaticPrivate PrivateKey,
	responderStaticPublic PublicKey,
) (HandshakeInitiation, HandshakeState, error) {
	initiatorStaticPublic, err := initiatorStaticPrivate.PublicKey()
	if err != nil {
		return HandshakeInitiation{}, HandshakeState{}, err
	}

	state := NewHandshakeState(responderStaticPublic)
	var message HandshakeInitiation

	message.SenderIndex, err = generateSenderIndex()
	if err != nil {
		return HandshakeInitiation{}, HandshakeState{}, err
	}

	ephemeralPrivate, err := state.setInitiationEphemeral(&message)
	if err != nil {
		return HandshakeInitiation{}, HandshakeState{}, err
	}

	staticEncryptionKey, err := state.deriveInitiationStaticEncryptionKey(
		ephemeralPrivate,
		responderStaticPublic,
	)
	if err != nil {
		return HandshakeInitiation{}, HandshakeState{}, err
	}
	if err := state.encryptInitiationStatic(
		&message,
		staticEncryptionKey,
		initiatorStaticPublic,
	); err != nil {
		return HandshakeInitiation{}, HandshakeState{}, err
	}

	timestampEncryptionKey, err := state.deriveInitiationTimestampEncryptionKey(
		initiatorStaticPrivate,
		responderStaticPublic,
	)
	if err != nil {
		return HandshakeInitiation{}, HandshakeState{}, err
	}
	if err := state.encryptInitiationTimestamp(
		&message,
		timestampEncryptionKey,
		newTAI64NTimestamp(time.Now()),
	); err != nil {
		return HandshakeInitiation{}, HandshakeState{}, err
	}

	// The authenticators are not part of the Noise transcript.
	setInitiationMAC1(&message, responderStaticPublic)
	setInitiationMAC2(&message)
	return message, state, nil
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

func (state *HandshakeState) mixHash(data []byte) {
	hashInput := make([]byte, 0, len(state.Hash)+len(data))
	hashInput = append(hashInput, state.Hash[:]...)
	hashInput = append(hashInput, data...)
	state.Hash = blake2s.Sum256(hashInput)
}

func (state *HandshakeState) mixKey(input []byte) {
	temporary := hmacBlake2s(state.ChainingKey[:], input)
	state.ChainingKey = hmacBlake2s(temporary[:], []byte{1})
}

func (state *HandshakeState) mixKeyAndGetEncryptionKey(input []byte) [HashSize]byte {
	temporary := hmacBlake2s(state.ChainingKey[:], input)
	state.ChainingKey = hmacBlake2s(temporary[:], []byte{1})

	keyInput := make([]byte, 0, len(state.ChainingKey)+1)
	keyInput = append(keyInput, state.ChainingKey[:]...)
	keyInput = append(keyInput, 2)
	return hmacBlake2s(temporary[:], keyInput)
}

// The extra hash output makes an unset preshared key harmless: peers that
// disagree about one reach different transcripts instead of a weaker session.
func (state *HandshakeState) mixKeyHashAndGetEncryptionKey(input []byte) [HashSize]byte {
	temporary := hmacBlake2s(state.ChainingKey[:], input)
	state.ChainingKey = hmacBlake2s(temporary[:], []byte{1})

	hashInput := make([]byte, 0, len(state.ChainingKey)+1)
	hashInput = append(hashInput, state.ChainingKey[:]...)
	hashInput = append(hashInput, 2)
	hashMixin := hmacBlake2s(temporary[:], hashInput)

	keyInput := make([]byte, 0, len(hashMixin)+1)
	keyInput = append(keyInput, hashMixin[:]...)
	keyInput = append(keyInput, 3)
	encryptionKey := hmacBlake2s(temporary[:], keyInput)

	state.mixHash(hashMixin[:])
	return encryptionKey
}

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

func hmacBlake2s(key, input []byte) [HashSize]byte {
	mac := hmac.New(newBlake2s256, key)
	_, _ = mac.Write(input)

	var result [HashSize]byte
	copy(result[:], mac.Sum(nil))
	return result
}

func newBlake2s256() hash.Hash {
	hasher, err := blake2s.New256(nil)
	if err != nil {
		panic("create unkeyed BLAKE2s-256: " + err.Error())
	}
	return hasher
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

	// TODO: ECDH initiator ephemeral / responder ephemeral.

	// TODO: ECDH initiator static / responder ephemeral.

	// TODO: mix the all-zero preshared key and derive the AEAD key.

	// TODO: verify the tag over an empty plaintext and mix it into the hash.

	return message, state, nil
}
