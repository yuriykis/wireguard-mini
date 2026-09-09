package noise

import (
	"crypto/hmac"
	"hash"

	"golang.org/x/crypto/blake2s"
)

const (
	HashSize         = 32
	ChainingKeySize  = 32
	PresharedKeySize = 32

	noiseConstruction   = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
	wireGuardIdentifier = "WireGuard v1 zx2c4 Jason@zx2c4.com"
)

// HandshakeState holds the two evolving 32-byte values used by Noise.
type HandshakeState struct {
	Hash        [HashSize]byte
	ChainingKey [ChainingKeySize]byte
	IsInitiator bool
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
