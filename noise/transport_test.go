package noise

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDeriveTransportKeysAssignsRolesByInitiator(t *testing.T) {
	state := NewHandshakeState(PublicKey{9})
	first, second := kdf2(state.ChainingKey[:], nil)

	initiator := state
	initiator.IsInitiator = true
	responder := state
	responder.IsInitiator = false

	require.Equal(t, TransportKeys{Send: first, Receive: second}, initiator.DeriveTransportKeys())
	require.Equal(t, TransportKeys{Send: second, Receive: first}, responder.DeriveTransportKeys())
	require.Equal(t, [ChainingKeySize]byte{}, initiator.ChainingKey)
	require.Equal(t, [ChainingKeySize]byte{}, responder.ChainingKey)
}

func TestDeriveTransportKeysPairUpAfterAFullHandshake(t *testing.T) {
	initiatorStaticPrivate, err := GeneratePrivateKey()
	require.NoError(t, err)
	responderStaticPrivate, err := GeneratePrivateKey()
	require.NoError(t, err)
	responderStaticPublic, err := responderStaticPrivate.PublicKey()
	require.NoError(t, err)

	initiation, initiatorEphemeralPrivate, initiatorStateAfterInitiation, err := CreateInitiation(
		initiatorStaticPrivate,
		responderStaticPublic,
	)
	require.NoError(t, err)

	_, initiatorStaticPublic, _, responderStateAfterInitiation, err := ConsumeInitiation(
		responderStaticPrivate,
		initiation.MarshalBinary(),
	)
	require.NoError(t, err)

	response, responderState, err := CreateResponse(
		initiatorStaticPublic,
		initiation,
		responderStateAfterInitiation,
	)
	require.NoError(t, err)

	_, initiatorState, err := ConsumeResponse(
		initiatorStaticPrivate,
		initiatorEphemeralPrivate,
		response.MarshalBinary(),
		initiatorStateAfterInitiation,
	)
	require.NoError(t, err)

	initiatorKeys := initiatorState.DeriveTransportKeys()
	responderKeys := responderState.DeriveTransportKeys()

	require.Equal(t, initiatorKeys.Send, responderKeys.Receive)
	require.Equal(t, initiatorKeys.Receive, responderKeys.Send)
	require.NotEqual(t, initiatorKeys.Send, initiatorKeys.Receive)
}

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
