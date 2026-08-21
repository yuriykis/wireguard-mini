package noise

import (
	"bytes"
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

func TestNewTAI64NTimestampIsOrderedByteWise(t *testing.T) {
	// A responder rejects a replayed initiation by comparing the raw bytes of
	// the received timestamp with the last one it accepted, so a later moment
	// has to produce a lexicographically greater value.
	tests := []struct {
		name    string
		earlier time.Time
		later   time.Time
	}{
		{
			name:    "later second",
			earlier: time.Unix(1_700_000_000, 0),
			later:   time.Unix(1_700_000_001, 0),
		},
		{
			name:    "later nanosecond within the same second",
			earlier: time.Unix(1_700_000_000, 0),
			later:   time.Unix(1_700_000_000, 100_000_000),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			earlier := newTAI64NTimestamp(tt.earlier)
			later := newTAI64NTimestamp(tt.later)

			require.Negative(t, bytes.Compare(earlier[:], later[:]))
		})
	}
}

func TestNewTAI64NTimestampWhitensLowNanosecondBits(t *testing.T) {
	// The lowest nanosecond bits are cleared on purpose: they would expose the
	// precision of the local clock without adding anything to replay
	// protection.
	coarse := newTAI64NTimestamp(time.Unix(1_700_000_000, 100_000_000))
	fine := newTAI64NTimestamp(time.Unix(1_700_000_000, 100_000_001))

	require.Equal(t, coarse, fine)
}
