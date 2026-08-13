package noise

const (
	HashSize        = 32
	ChainingKeySize = 32
)

// HandshakeState contains the two evolving 32-byte values used by Noise
// while a handshake is being constructed or processed.
type HandshakeState struct {
	Hash        [HashSize]byte
	ChainingKey [ChainingKeySize]byte
}
