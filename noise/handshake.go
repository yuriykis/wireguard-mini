package noise

import "golang.org/x/crypto/blake2s"

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
	handshakeHash := blake2s.Sum256(hashInput)

	hashInput = make([]byte, 0, len(handshakeHash)+len(responderPublicKey))
	hashInput = append(hashInput, handshakeHash[:]...)
	hashInput = append(hashInput, responderPublicKey[:]...)
	handshakeHash = blake2s.Sum256(hashInput)

	return HandshakeState{
		Hash:        handshakeHash,
		ChainingKey: chainingKey,
	}
}
