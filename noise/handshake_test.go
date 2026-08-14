package noise

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewHandshakeState(t *testing.T) {
	responderPublicKey := PublicKey{9}

	state := NewHandshakeState(responderPublicKey)

	require.Equal(t,
		"60e26daef327efc02ec335e2a025d2d016eb4206f87277f52d38d1988b78cd36",
		hex.EncodeToString(state.ChainingKey[:]),
	)
	require.Equal(t,
		"575bad75a5a30f85f58df113422a55d41873e357b40a3a2ea91f456c9508211a",
		hex.EncodeToString(state.Hash[:]),
	)
}

func TestSetInitiationEphemeral(t *testing.T) {
	state := NewHandshakeState(PublicKey{9})
	expectedState := state
	message := HandshakeInitiation{SenderIndex: 42}

	ephemeralPrivate, err := state.setInitiationEphemeral(&message)

	require.NoError(t, err)
	ephemeralPublic, err := ephemeralPrivate.PublicKey()
	require.NoError(t, err)
	require.Equal(t, ephemeralPublic[:], message.UnencryptedEphemeral[:])

	expectedState.mixHash(message.UnencryptedEphemeral[:])
	expectedState.mixKey(message.UnencryptedEphemeral[:])
	require.Equal(t, expectedState.Hash, state.Hash)
	require.Equal(t, expectedState.ChainingKey, state.ChainingKey)
	require.Equal(t, uint32(42), message.SenderIndex)
	require.Equal(t, [48]byte{}, message.EncryptedStatic)
	require.Equal(t, [28]byte{}, message.EncryptedTimestamp)
}

func TestMixHash(t *testing.T) {
	state := NewHandshakeState(PublicKey{9})
	chainingKeyBefore := state.ChainingKey

	state.mixHash([]byte{1, 2, 3})

	require.Equal(t,
		"9bd1c5f9faf06d2e88b162d6e77ed1d76f01b5b02b5a115901f9cc19d3922458",
		hex.EncodeToString(state.Hash[:]),
	)
	require.Equal(t, chainingKeyBefore, state.ChainingKey)
}

func TestMixKey(t *testing.T) {
	state := NewHandshakeState(PublicKey{9})
	hashBefore := state.Hash
	ephemeralPublicKey := PublicKey{9}

	state.mixKey(ephemeralPublicKey[:])

	require.Equal(t,
		"394f055beb127aba9d424e2196e0bb2bfa08846ba4d3739600ff8bbd4dc4c7e6",
		hex.EncodeToString(state.ChainingKey[:]),
	)
	require.Equal(t, hashBefore, state.Hash)
}

func TestMixKeyAndGetEncryptionKey(t *testing.T) {
	state := NewHandshakeState(PublicKey{9})
	hashBefore := state.Hash

	encryptionKey := state.mixKeyAndGetEncryptionKey([]byte{1, 2, 3})

	require.Equal(t,
		"392064a312d512fc32d7a176879d306885d000aaecd19a05a143d6bbdd6ab7a0",
		hex.EncodeToString(state.ChainingKey[:]),
	)
	require.Equal(t,
		"c20abf72ebebd5c884c1ea79458a2038a2b1da673d3de47a6e29913e096bdbb8",
		hex.EncodeToString(encryptionKey[:]),
	)
	require.Equal(t, hashBefore, state.Hash)
}
