package noise

import (
	"crypto/hmac"
	"hash"

	"golang.org/x/crypto/blake2s"
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
