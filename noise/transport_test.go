package noise

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestKDF2(t *testing.T) {
	state := NewHandshakeState(PublicKey{9})

	first, second := kdf2(state.ChainingKey[:], nil)

	// Recomputed the way the whitepaper defines KDF2, so the test pins the
	// construction and not just the fact that two values came out.
	temporary := hmacBlake2s(state.ChainingKey[:], nil)
	expectedFirst := hmacBlake2s(temporary[:], []byte{1})
	expectedSecond := hmacBlake2s(temporary[:], append(append([]byte{}, expectedFirst[:]...), 2))

	require.Equal(t, expectedFirst, first)
	require.Equal(t, expectedSecond, second)
	require.NotEqual(t, first, second)
}

func TestKDF2IsDeterministic(t *testing.T) {
	chainingKey := NewHandshakeState(PublicKey{9}).ChainingKey

	first, second := kdf2(chainingKey[:], nil)
	firstAgain, secondAgain := kdf2(chainingKey[:], nil)

	require.Equal(t, first, firstAgain)
	require.Equal(t, second, secondAgain)
}

func TestKDF2MatchesMixKeyAndGetEncryptionKey(t *testing.T) {
	state := NewHandshakeState(PublicKey{9})

	first, second := kdf2(state.ChainingKey[:], []byte{1, 2, 3})
	encryptionKey := state.mixKeyAndGetEncryptionKey([]byte{1, 2, 3})

	require.Equal(t, state.ChainingKey, first)
	require.Equal(t, encryptionKey, second)
}
