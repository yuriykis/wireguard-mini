package noise

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/chacha20poly1305"
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

func TestEncryptTransportDataCanBeDecryptedWithSendKey(t *testing.T) {
	sendKey := [HashSize]byte{7}
	packet := []byte("ping packet")

	encrypted, err := EncryptTransportData(sendKey, 42, packet)
	require.NoError(t, err)

	require.Len(t, encrypted, len(packet)+chacha20poly1305.Overhead)
	require.NotContains(t, string(encrypted), string(packet))

	aead, err := chacha20poly1305.New(sendKey[:])
	require.NoError(t, err)
	var nonce [chacha20poly1305.NonceSize]byte
	binary.LittleEndian.PutUint64(nonce[4:], 42)
	decrypted, err := aead.Open(nil, nonce[:], encrypted, nil)
	require.NoError(t, err)
	require.Equal(t, packet, decrypted)
}

func TestEncryptTransportDataDiffersPerCounter(t *testing.T) {
	sendKey := [HashSize]byte{7}
	packet := []byte("ping packet")

	first, err := EncryptTransportData(sendKey, 1, packet)
	require.NoError(t, err)
	second, err := EncryptTransportData(sendKey, 2, packet)
	require.NoError(t, err)

	require.NotEqual(t, first, second)
}

func TestEncryptTransportDataCannotBeDecryptedWithAnotherCounter(t *testing.T) {
	sendKey := [HashSize]byte{7}

	encrypted, err := EncryptTransportData(sendKey, 1, []byte("ping packet"))
	require.NoError(t, err)

	aead, err := chacha20poly1305.New(sendKey[:])
	require.NoError(t, err)
	var nonce [chacha20poly1305.NonceSize]byte
	binary.LittleEndian.PutUint64(nonce[4:], 2)
	_, err = aead.Open(nil, nonce[:], encrypted, nil)
	require.Error(t, err)
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

func TestEncryptAndDecryptTransportDataAgree(t *testing.T) {
	key := [HashSize]byte{7}
	packet := []byte("ping packet")

	encrypted, err := EncryptTransportData(key, 42, packet)
	require.NoError(t, err)

	decrypted, err := DecryptTransportData(key, 42, encrypted)
	require.NoError(t, err)
	require.Equal(t, packet, decrypted)
}

func TestDecryptTransportDataRejectsAnotherCounter(t *testing.T) {
	key := [HashSize]byte{7}

	encrypted, err := EncryptTransportData(key, 1, []byte("ping packet"))
	require.NoError(t, err)

	_, err = DecryptTransportData(key, 2, encrypted)
	require.Error(t, err)
}

func TestDecryptTransportDataRejectsAnotherKey(t *testing.T) {
	encrypted, err := EncryptTransportData([HashSize]byte{7}, 1, []byte("ping packet"))
	require.NoError(t, err)

	_, err = DecryptTransportData([HashSize]byte{8}, 1, encrypted)
	require.Error(t, err)
}

func TestDecryptTransportDataRejectsModifiedPacket(t *testing.T) {
	key := [HashSize]byte{7}

	encrypted, err := EncryptTransportData(key, 1, []byte("ping packet"))
	require.NoError(t, err)
	encrypted[0] ^= 1

	_, err = DecryptTransportData(key, 1, encrypted)
	require.Error(t, err)
}
