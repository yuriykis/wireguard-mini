package noise

import (
	"crypto/hmac"
	"hash"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	HashSize        = 32
	ChainingKeySize = 32

	noiseConstruction   = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
	wireGuardIdentifier = "WireGuard v1 zx2c4 Jason@zx2c4.com"
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
