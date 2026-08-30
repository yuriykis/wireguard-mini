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

// HandshakeState contains the two evolving 32-byte values used by Noise
// while a handshake is being constructed or processed.
type HandshakeState struct {
	Hash        [HashSize]byte
	ChainingKey [ChainingKeySize]byte
}

// NewHandshakeState initializes the Noise state shared by an initiator and a
// responder. Both sides bind the handshake to the responder's static identity.
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

// CreateInitiation builds a complete handshake initiation message for the
// given peer. It returns the message together with the handshake state left
// behind after the last mixing step, which the caller needs to process the
// responder's reply.
func CreateInitiation(
	initiatorStaticPrivate PrivateKey,
	responderStaticPublic PublicKey,
) (HandshakeInitiation, HandshakeState, error) {
	initiatorStaticPublic, err := initiatorStaticPrivate.PublicKey()
	if err != nil {
		return HandshakeInitiation{}, HandshakeState{}, err
	}

	// The transcript is rebuilt in the same order the initiator built it, so
	// every AEAD tag below verifies only if both sides agree on every byte.
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

	// The two authenticators cover the finished message and are not part of
	// the Noise transcript, so they come last and do not touch the state.
	setInitiationMAC1(&message, responderStaticPublic)
	setInitiationMAC2(&message)
	return message, state, nil
}

// setInitiationEphemeral generates the initiator's ephemeral key pair, puts
// the public key in the message, and mixes that public value into the Noise
// handshake state. The private key is returned for the following ECDH step.
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

// consumeInitiationEphemeral mixes the initiator's ephemeral public key into
// the responder's handshake state. It is the mirror of setInitiationEphemeral
// with the key generation removed: the responder does not create this value,
// it reads it off the wire, but it must absorb it in exactly the same order to
// end up with the same transcript.
func (state *HandshakeState) consumeInitiationEphemeral(message HandshakeInitiation) {
	state.mixHash(message.UnencryptedEphemeral[:])
	state.mixKey(message.UnencryptedEphemeral[:])
}

// deriveInitiationStaticEncryptionKey performs ECDH between the initiator's
// ephemeral private key and the responder's static public key. It mixes the
// resulting shared secret into the handshake and returns the key that will
// encrypt the initiator's static public key.
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

// consumeInitiationStaticDecryptionKey performs ECDH between the responder's
// static private key and the initiator's ephemeral public key. Curve25519 is
// symmetric, so this produces the same shared secret the initiator obtained
// the other way round in deriveInitiationStaticEncryptionKey, and therefore
// the same key for the static field. This is the only secret the responder can
// compute before it knows who the initiator is.
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

// encryptInitiationStatic encrypts the initiator's static public key and
// authenticates it against the handshake hash accumulated so far. WireGuard
// uses counter zero here, which produces an all-zero ChaCha20-Poly1305 nonce.
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

// decryptInitiationStatic decrypts the initiator's static public key and
// mixes the ciphertext into the hash, mirroring encryptInitiationStatic. The
// handshake hash is the additional data, so the tag verifies only if the
// responder rebuilt the same transcript. A failure here means the message was
// tampered with, was addressed to somebody else, or was never valid, and the
// caller answers it with silence.
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

// deriveInitiationTimestampEncryptionKey performs ECDH between the
// initiator's and responder's static keys. It mixes the resulting shared
// secret into the handshake and returns the key that will encrypt the
// initiation timestamp.
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

// consumeInitiationTimestampDecryptionKey performs ECDH between the
// responder's static private key and the initiator's static public key learned
// from the previous field. This is the step that authenticates the initiator:
// only the holder of the matching static private key can produce a message
// whose timestamp tag verifies. It is also the pair of keys that stays the
// same across every handshake between these two peers.
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

// encryptInitiationTimestamp encrypts the TAI64N timestamp and authenticates
// it against the handshake hash accumulated so far.
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

// decryptInitiationTimestamp decrypts the TAI64N timestamp and mixes the
// ciphertext into the hash, mirroring encryptInitiationTimestamp. This tag is
// the one that proves the initiator holds the static private key matching the
// identity it claimed, because the key comes from the static-static ECDH.
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

// encryptResponseNothing encrypts an empty plaintext and stores the resulting
// 16-byte tag in the message, then absorbs that tag into the transcript hash.
//
// There is nothing to hide in the second message, so the payload is empty and
// the ciphertext is the authentication tag alone. The tag is computed over the
// handshake hash as additional data, which by now covers every value both
// sides have exchanged and every secret they derived from them. Verifying it
// therefore proves the sender rebuilt a byte-identical transcript, which only
// the holder of the responder's static private key could do. This one tag is
// the whole cryptographic content of the response.
//
// WireGuard uses counter zero here, which produces an all-zero
// ChaCha20-Poly1305 nonce, exactly as in the initiation.
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

// mixHash appends data to the transcript by hashing the current handshake hash
// together with the new bytes.
func (state *HandshakeState) mixHash(data []byte) {
	hashInput := make([]byte, 0, len(state.Hash)+len(data))
	hashInput = append(hashInput, state.Hash[:]...)
	hashInput = append(hashInput, data...)
	state.Hash = blake2s.Sum256(hashInput)
}

// mixKey uses WireGuard's single-output KDF to mix input into the chaining key.
func (state *HandshakeState) mixKey(input []byte) {
	temporary := hmacBlake2s(state.ChainingKey[:], input)
	state.ChainingKey = hmacBlake2s(temporary[:], []byte{1})
}

// mixKeyAndGetEncryptionKey uses WireGuard's two-output KDF. It mixes input
// into the chaining key and returns a separate key for an AEAD operation.
func (state *HandshakeState) mixKeyAndGetEncryptionKey(input []byte) [HashSize]byte {
	temporary := hmacBlake2s(state.ChainingKey[:], input)
	state.ChainingKey = hmacBlake2s(temporary[:], []byte{1})

	keyInput := make([]byte, 0, len(state.ChainingKey)+1)
	keyInput = append(keyInput, state.ChainingKey[:]...)
	keyInput = append(keyInput, 2)
	return hmacBlake2s(temporary[:], keyInput)
}

// mixKeyHashAndGetEncryptionKey uses WireGuard's three-output KDF. It mixes
// input into the chaining key, absorbs the second output into the transcript
// hash, and returns the third output as a key for an AEAD operation.
//
// The handshake uses this only once, for the preshared key. The extra output
// is what makes an unset preshared key harmless: even an all-zero value still
// travels through the chaining key and the hash, so a peer that has one
// configured and a peer that does not end up with different transcripts and
// simply fail to talk to each other, rather than silently agreeing on a
// weaker session.
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

// deriveMAC1Key binds MAC1 to the responder's static identity.
func deriveMAC1Key(responderPublicKey PublicKey) [HashSize]byte {
	input := make([]byte, 0, len(labelMAC1)+len(responderPublicKey))
	input = append(input, labelMAC1...)
	input = append(input, responderPublicKey[:]...)
	return blake2s.Sum256(input)
}

// calculateMAC1 authenticates data with keyed BLAKE2s and returns its
// 16-byte output required by the WireGuard message format.
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

// setInitiationMAC1 calculates MAC1 over all handshake initiation fields that
// precede MAC1 and stores the result in the message. MAC2 is left unchanged.
func setInitiationMAC1(message *HandshakeInitiation, responderPublicKey PublicKey) {
	data := message.MarshalBinary()
	mac1Key := deriveMAC1Key(responderPublicKey)
	message.MAC1 = calculateMAC1(mac1Key, data[:mac1Offset])
}

// verifyInitiationMAC1 recomputes MAC1 over the raw bytes that precede it and
// compares it with the value carried by the message. The comparison is
// constant time, because a MAC compared byte by byte can be guessed one byte
// at a time by timing the answers.
func verifyInitiationMAC1(data []byte, responderPublicKey PublicKey) error {
	mac1Key := deriveMAC1Key(responderPublicKey)
	expected := calculateMAC1(mac1Key, data[:mac1Offset])

	if !hmac.Equal(expected[:], data[mac1Offset:mac2Offset]) {
		return errors.New("handshake initiation MAC1 mismatch")
	}
	return nil
}

// setInitiationMAC2 fills the second message authenticator. MAC2 exists only
// for WireGuard's cookie-based DoS mitigation: an initiator that has not been
// given a cookie sends an all-zero MAC2, and a responder that is not under
// load accepts it. Cookies are out of scope for this implementation, so MAC2
// is always zero here. Zeroing it explicitly keeps that a decision rather than
// an omission, and guarantees the field is clean even when the caller reuses a
// message value.
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

// generateSenderIndex draws the initiator's local session identifier. The
// value travels in cleartext and has no cryptographic role, so it only has to
// be unpredictable enough not to leak how many sessions this host has run.
func generateSenderIndex() (uint32, error) {
	var indexBytes [4]byte
	if _, err := rand.Read(indexBytes[:]); err != nil {
		return 0, fmt.Errorf("generate sender index: %w", err)
	}

	return binary.LittleEndian.Uint32(indexBytes[:]), nil
}

// ConsumeInitiation processes a handshake initiation received from the wire.
// It is the responder's mirror image of CreateInitiation: it replays the same
// mixing steps in the same order, and every AEAD tag verifies only if both
// sides arrived at an identical transcript.
//
// It returns the initiator's static public key, which is how the responder
// learns who is talking to it, the timestamp the initiator claimed, and the
// handshake state left behind, which is needed to build the response.
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

	// The transcript is rebuilt in the same order the initiator built it, so
	// every AEAD tag below verifies only if both sides agree on every byte.
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

	// The timestamp is returned rather than checked. Rejecting one that is not
	// newer than the last seen from this peer needs a peer table, which does
	// not exist yet, and that check is the protocol's replay defence.
	timestamp, err := state.decryptInitiationTimestamp(message, timestampDecryptionKey)
	if err != nil {
		return HandshakeInitiation{}, PublicKey{}, tai64nTimestamp{}, HandshakeState{}, err
	}

	return message, initiatorStaticPublic, timestamp, state, nil
}

// CreateResponse builds the handshake response, WireGuard's second message.
// It is the responder's answer to an initiation that ConsumeInitiation has
// already accepted, so it starts from the state that call left behind and
// continues the very same transcript.
//
// The message carries no identity and no payload. Its whole job is to hand the
// initiator a fresh ephemeral public key and one AEAD tag over an empty
// plaintext. That tag verifies only if the initiator reaches a byte-identical
// transcript, which proves the responder holds the right static key and
// completed the same two Diffie-Hellman exchanges.
//
// It returns the message together with the handshake state left behind, from
// which both sides will later derive the transport keys.
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

	// An all-zero preshared key is what WireGuard uses when the optional
	// symmetric key is not configured, and it is what this implementation
	// always uses.
	var presharedKey [PresharedKeySize]byte
	encryptionKey := state.mixKeyHashAndGetEncryptionKey(presharedKey[:])

	if err := state.encryptResponseNothing(&message, encryptionKey); err != nil {
		return HandshakeResponse{}, HandshakeState{}, err
	}

	// 7. Fill MAC1 over the finished message. Unlike the initiation, this MAC
	//    is keyed on the initiator's static public key, because it authorizes
	//    the message towards the initiator. MAC2 stays zero: cookies are out
	//    of scope.

	return HandshakeResponse{}, state, errors.New("CreateResponse is not implemented yet")
}

// mixResponseEphemeralSharedSecret performs ECDH between the responder's fresh
// ephemeral private key and the initiator's ephemeral public key read from the
// initiation, and mixes the result into the chaining key.
//
// This is the exchange that gives the session forward secrecy: both halves are
// thrown away when the handshake ends, so an attacker who later steals either
// side's static private key still cannot reconstruct this secret and cannot
// decrypt recorded traffic. Nothing is encrypted at this point, so the plain
// mixKey is used and no encryption key is derived.
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

// mixResponseStaticSharedSecret performs ECDH between the responder's
// ephemeral private key and the static public key of the initiator, which the
// responder learned by decrypting the initiation, and mixes the result into
// the chaining key.
//
// This is the step that ties the fresh session to an identity. Only the holder
// of the matching static private key can compute the same secret, so only that
// peer will reach the same transcript and be able to verify the tag the
// response carries. Like the previous exchange it encrypts nothing yet, so the
// plain mixKey is used.
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

// setResponseEphemeral generates the responder's ephemeral key pair, puts the
// public key in the message, and mixes that public value into the handshake
// state. It is the exact counterpart of setInitiationEphemeral: the same two
// mixing steps in the same order, because the initiator will replay them from
// the value it reads off the wire and both sides have to reach an identical
// transcript. The private key is returned for the two ECDH steps that follow.
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
