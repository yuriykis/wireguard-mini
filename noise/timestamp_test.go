package noise

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/chacha20poly1305"
)

func TestNewTAI64NTimestamp(t *testing.T) {
	timestamp := newTAI64NTimestamp(time.Unix(1_700_000_000, 123_456_789))

	require.Equal(t, "400000006553f10a07000000", hex.EncodeToString(timestamp[:]))
}

func TestEncryptInitiationTimestamp(t *testing.T) {
	state := NewHandshakeState(PublicKey{9})
	hashBefore := state.Hash
	expectedState := state
	message := HandshakeInitiation{}
	encryptionKey := [HashSize]byte{1}
	timestamp := newTAI64NTimestamp(time.Unix(1_700_000_000, 123_456_789))

	err := state.encryptInitiationTimestamp(&message, encryptionKey, timestamp)

	require.NoError(t, err)
	require.NotEqual(t, [28]byte{}, message.EncryptedTimestamp)
	aead, err := chacha20poly1305.New(encryptionKey[:])
	require.NoError(t, err)
	var nonce [chacha20poly1305.NonceSize]byte
	decryptedTimestamp, err := aead.Open(
		nil,
		nonce[:],
		message.EncryptedTimestamp[:],
		hashBefore[:],
	)
	require.NoError(t, err)
	require.Equal(t, timestamp[:], decryptedTimestamp)

	expectedState.mixHash(message.EncryptedTimestamp[:])
	require.Equal(t, expectedState.Hash, state.Hash)
	require.Equal(t, expectedState.ChainingKey, state.ChainingKey)
}
