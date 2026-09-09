package noise

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/chacha20poly1305"
)

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

func TestDeriveInitiationStaticEncryptionKey(t *testing.T) {
	responderStaticPrivate, err := GeneratePrivateKey()
	require.NoError(t, err)
	responderStaticPublic, err := responderStaticPrivate.PublicKey()
	require.NoError(t, err)
	state := NewHandshakeState(responderStaticPublic)
	message := HandshakeInitiation{}
	ephemeralPrivate, err := state.setInitiationEphemeral(&message)
	require.NoError(t, err)
	hashBefore := state.Hash
	expectedState := state

	encryptionKey, err := state.deriveInitiationStaticEncryptionKey(
		ephemeralPrivate,
		responderStaticPublic,
	)

	require.NoError(t, err)
	ephemeralPublic := PublicKey(message.UnencryptedEphemeral)
	sharedSecret, err := responderStaticPrivate.SharedSecret(ephemeralPublic)
	require.NoError(t, err)
	expectedEncryptionKey := expectedState.mixKeyAndGetEncryptionKey(sharedSecret[:])
	require.Equal(t, expectedEncryptionKey, encryptionKey)
	require.Equal(t, expectedState.ChainingKey, state.ChainingKey)
	require.Equal(t, hashBefore, state.Hash)
}

func TestEncryptInitiationStatic(t *testing.T) {
	state := NewHandshakeState(PublicKey{9})
	hashBefore := state.Hash
	expectedState := state
	message := HandshakeInitiation{}
	encryptionKey := [HashSize]byte{1}
	initiatorStaticPublic := PublicKey{2}

	err := state.encryptInitiationStatic(
		&message,
		encryptionKey,
		initiatorStaticPublic,
	)

	require.NoError(t, err)
	require.NotEqual(t, [48]byte{}, message.EncryptedStatic)
	aead, err := chacha20poly1305.New(encryptionKey[:])
	require.NoError(t, err)
	var nonce [chacha20poly1305.NonceSize]byte
	decryptedStatic, err := aead.Open(
		nil,
		nonce[:],
		message.EncryptedStatic[:],
		hashBefore[:],
	)
	require.NoError(t, err)
	require.Equal(t, initiatorStaticPublic[:], decryptedStatic)

	expectedState.mixHash(message.EncryptedStatic[:])
	require.Equal(t, expectedState.Hash, state.Hash)
	require.Equal(t, expectedState.ChainingKey, state.ChainingKey)
}

func TestDeriveInitiationTimestampEncryptionKey(t *testing.T) {
	initiatorStaticPrivate, err := GeneratePrivateKey()
	require.NoError(t, err)
	initiatorStaticPublic, err := initiatorStaticPrivate.PublicKey()
	require.NoError(t, err)
	responderStaticPrivate, err := GeneratePrivateKey()
	require.NoError(t, err)
	responderStaticPublic, err := responderStaticPrivate.PublicKey()
	require.NoError(t, err)

	state := NewHandshakeState(responderStaticPublic)
	message := HandshakeInitiation{}
	ephemeralPrivate, err := state.setInitiationEphemeral(&message)
	require.NoError(t, err)
	staticEncryptionKey, err := state.deriveInitiationStaticEncryptionKey(
		ephemeralPrivate,
		responderStaticPublic,
	)
	require.NoError(t, err)
	err = state.encryptInitiationStatic(
		&message,
		staticEncryptionKey,
		initiatorStaticPublic,
	)
	require.NoError(t, err)
	hashBefore := state.Hash
	expectedState := state

	timestampEncryptionKey, err := state.deriveInitiationTimestampEncryptionKey(
		initiatorStaticPrivate,
		responderStaticPublic,
	)

	require.NoError(t, err)
	sharedSecret, err := responderStaticPrivate.SharedSecret(initiatorStaticPublic)
	require.NoError(t, err)
	expectedTimestampEncryptionKey := expectedState.mixKeyAndGetEncryptionKey(sharedSecret[:])
	require.Equal(t, expectedTimestampEncryptionKey, timestampEncryptionKey)
	require.Equal(t, expectedState.ChainingKey, state.ChainingKey)
	require.Equal(t, hashBefore, state.Hash)
}

func TestCreateInitiationFillsEveryField(t *testing.T) {
	initiatorPrivate, err := GeneratePrivateKey()
	require.NoError(t, err)
	responderPrivate, err := GeneratePrivateKey()
	require.NoError(t, err)
	responderPublic, err := responderPrivate.PublicKey()
	require.NoError(t, err)

	message, _, _, err := CreateInitiation(initiatorPrivate, responderPublic)
	require.NoError(t, err)

	require.NotEqual(t, [32]byte{}, message.UnencryptedEphemeral)
	require.NotEqual(t, [48]byte{}, message.EncryptedStatic)
	require.NotEqual(t, [28]byte{}, message.EncryptedTimestamp)
	require.NotEqual(t, [16]byte{}, message.MAC1)
	require.Equal(t, [16]byte{}, message.MAC2)

	expectedMAC1 := message
	setInitiationMAC1(&expectedMAC1, responderPublic)
	require.Equal(t, expectedMAC1.MAC1, message.MAC1)

	parsed, err := ParseHandshakeInitiation(message.MarshalBinary())
	require.NoError(t, err)
	require.Equal(t, message, parsed)
}

func TestCreateInitiationUsesFreshEphemeralEveryTime(t *testing.T) {
	initiatorPrivate, err := GeneratePrivateKey()
	require.NoError(t, err)
	responderPrivate, err := GeneratePrivateKey()
	require.NoError(t, err)
	responderPublic, err := responderPrivate.PublicKey()
	require.NoError(t, err)

	first, _, firstState, err := CreateInitiation(initiatorPrivate, responderPublic)
	require.NoError(t, err)
	second, _, secondState, err := CreateInitiation(initiatorPrivate, responderPublic)
	require.NoError(t, err)

	require.NotEqual(t, first.UnencryptedEphemeral, second.UnencryptedEphemeral)
	require.NotEqual(t, first.EncryptedStatic, second.EncryptedStatic)
	require.NotEqual(t, firstState.ChainingKey, secondState.ChainingKey)
}

// TestCreateInitiationIsReadableByTheResponder replays the responder's half of
// the handshake by hand. It is the real proof that the initiation is correct:
// the responder mixes the same values in the same order, and both AEAD tags
// verify only if every step matches.
func TestCreateInitiationIsReadableByTheResponder(t *testing.T) {
	initiatorPrivate, err := GeneratePrivateKey()
	require.NoError(t, err)
	initiatorPublic, err := initiatorPrivate.PublicKey()
	require.NoError(t, err)
	responderPrivate, err := GeneratePrivateKey()
	require.NoError(t, err)
	responderPublic, err := responderPrivate.PublicKey()
	require.NoError(t, err)

	before := newTAI64NTimestamp(time.Now())
	message, _, initiatorState, err := CreateInitiation(initiatorPrivate, responderPublic)
	require.NoError(t, err)
	after := newTAI64NTimestamp(time.Now())

	state := NewHandshakeState(responderPublic)
	state.mixHash(message.UnencryptedEphemeral[:])
	state.mixKey(message.UnencryptedEphemeral[:])

	ephemeralSecret, err := responderPrivate.SharedSecret(message.UnencryptedEphemeral)
	require.NoError(t, err)
	staticKey := state.mixKeyAndGetEncryptionKey(ephemeralSecret[:])
	decryptedStatic := decryptForTest(t, staticKey, message.EncryptedStatic[:], state.Hash[:])
	require.Equal(t, initiatorPublic[:], decryptedStatic)
	state.mixHash(message.EncryptedStatic[:])

	var decryptedStaticKey PublicKey
	copy(decryptedStaticKey[:], decryptedStatic)
	staticSecret, err := responderPrivate.SharedSecret(decryptedStaticKey)
	require.NoError(t, err)
	timestampKey := state.mixKeyAndGetEncryptionKey(staticSecret[:])
	decryptedTimestamp := decryptForTest(t, timestampKey, message.EncryptedTimestamp[:], state.Hash[:])
	state.mixHash(message.EncryptedTimestamp[:])

	require.GreaterOrEqual(t, string(decryptedTimestamp), string(before[:]))
	require.LessOrEqual(t, string(decryptedTimestamp), string(after[:]))
	require.Equal(t, initiatorState.Hash, state.Hash)
	require.Equal(t, initiatorState.ChainingKey, state.ChainingKey)
}

func decryptForTest(t *testing.T, key [HashSize]byte, ciphertext, additionalData []byte) []byte {
	t.Helper()

	aead, err := chacha20poly1305.New(key[:])
	require.NoError(t, err)

	var nonce [chacha20poly1305.NonceSize]byte
	plaintext, err := aead.Open(nil, nonce[:], ciphertext, additionalData)
	require.NoError(t, err)
	return plaintext
}

func TestConsumeInitiationRejectsMalformedMessage(t *testing.T) {
	responderPrivate, err := GeneratePrivateKey()
	require.NoError(t, err)

	valid := testHandshakeInitiation().MarshalBinary()

	tests := []struct {
		name    string
		data    []byte
		wantErr string
	}{
		{name: "too short", data: valid[:HandshakeInitiationSize-1], wantErr: "invalid handshake initiation length"},
		{name: "wrong type", data: withByte(valid, 0, 2), wantErr: "invalid handshake initiation type"},
		{name: "non-zero reserved byte", data: withByte(valid, 2, 1), wantErr: "reserved bytes must be zero"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, _, _, err := ConsumeInitiation(responderPrivate, tt.data)
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestConsumeInitiationParsesEveryField(t *testing.T) {
	initiatorPrivate, err := GeneratePrivateKey()
	require.NoError(t, err)
	responderPrivate, err := GeneratePrivateKey()
	require.NoError(t, err)
	responderPublic, err := responderPrivate.PublicKey()
	require.NoError(t, err)

	want, _, _, err := CreateInitiation(initiatorPrivate, responderPublic)
	require.NoError(t, err)

	got, _, _, _, err := ConsumeInitiation(responderPrivate, want.MarshalBinary())

	require.NoError(t, err)
	require.Equal(t, want, got)
}

func TestConsumeInitiationRejectsWrongMAC1(t *testing.T) {
	initiatorPrivate, err := GeneratePrivateKey()
	require.NoError(t, err)
	responderPrivate, err := GeneratePrivateKey()
	require.NoError(t, err)
	responderPublic, err := responderPrivate.PublicKey()
	require.NoError(t, err)

	message, _, _, err := CreateInitiation(initiatorPrivate, responderPublic)
	require.NoError(t, err)

	t.Run("tampered mac1", func(t *testing.T) {
		data := message.MarshalBinary()
		data[mac1Offset] ^= 0x01

		_, _, _, _, err := ConsumeInitiation(responderPrivate, data)

		require.ErrorContains(t, err, "MAC1 mismatch")
	})

	t.Run("tampered payload", func(t *testing.T) {
		data := message.MarshalBinary()
		data[ephemeralOffset] ^= 0x01

		_, _, _, _, err := ConsumeInitiation(responderPrivate, data)

		require.ErrorContains(t, err, "MAC1 mismatch")
	})

	t.Run("addressed to another responder", func(t *testing.T) {
		otherPrivate, err := GeneratePrivateKey()
		require.NoError(t, err)

		_, _, _, _, err = ConsumeInitiation(otherPrivate, message.MarshalBinary())

		require.ErrorContains(t, err, "MAC1 mismatch")
	})
}

func TestConsumeInitiationAcceptsNonZeroMAC2(t *testing.T) {
	initiatorPrivate, err := GeneratePrivateKey()
	require.NoError(t, err)
	responderPrivate, err := GeneratePrivateKey()
	require.NoError(t, err)
	responderPublic, err := responderPrivate.PublicKey()
	require.NoError(t, err)

	message, _, _, err := CreateInitiation(initiatorPrivate, responderPublic)
	require.NoError(t, err)

	// A peer that already holds a cookie, such as the kernel implementation
	// under load, fills MAC2 with a real value. MAC1 covers only the bytes
	// before it and MAC2 itself is not verified here, so such a message must
	// still be accepted and must yield exactly the same result.
	withoutCookie := message.MarshalBinary()
	withCookie := message.MarshalBinary()
	for i := range withCookie[mac2Offset:] {
		withCookie[mac2Offset+i] = byte(i + 1)
	}

	wantMessage, wantStatic, wantTimestamp, wantState, err := ConsumeInitiation(responderPrivate, withoutCookie)
	require.NoError(t, err)

	gotMessage, gotStatic, gotTimestamp, gotState, err := ConsumeInitiation(responderPrivate, withCookie)

	require.NoError(t, err)
	require.Equal(t, withCookie[mac2Offset:], gotMessage.MAC2[:])
	require.Equal(t, wantMessage.MAC1, gotMessage.MAC1)
	require.Equal(t, wantStatic, gotStatic)
	require.Equal(t, wantTimestamp, gotTimestamp)
	require.Equal(t, wantState, gotState)
}

func TestConsumeInitiationRebuildsTheTranscript(t *testing.T) {
	initiatorPrivate, err := GeneratePrivateKey()
	require.NoError(t, err)
	initiatorPublic, err := initiatorPrivate.PublicKey()
	require.NoError(t, err)
	responderPrivate, err := GeneratePrivateKey()
	require.NoError(t, err)
	responderPublic, err := responderPrivate.PublicKey()
	require.NoError(t, err)

	message, _, _, err := CreateInitiation(initiatorPrivate, responderPublic)
	require.NoError(t, err)

	// Rebuild the responder's transcript step by step from the wire values and
	// the responder's own private key, without calling the code under test.
	var initiatorEphemeralPublic PublicKey
	copy(initiatorEphemeralPublic[:], message.UnencryptedEphemeral[:])
	ephemeralSharedSecret, err := responderPrivate.SharedSecret(initiatorEphemeralPublic)
	require.NoError(t, err)
	staticSharedSecret, err := responderPrivate.SharedSecret(initiatorPublic)
	require.NoError(t, err)

	want := NewHandshakeState(responderPublic)
	want.mixHash(message.UnencryptedEphemeral[:])
	want.mixKey(message.UnencryptedEphemeral[:])
	want.mixKeyAndGetEncryptionKey(ephemeralSharedSecret[:])
	want.mixHash(message.EncryptedStatic[:])
	want.mixKeyAndGetEncryptionKey(staticSharedSecret[:])
	want.mixHash(message.EncryptedTimestamp[:])

	_, _, _, got, err := ConsumeInitiation(responderPrivate, message.MarshalBinary())

	require.NoError(t, err)
	require.Equal(t, want, got)
}

func TestConsumeInitiationStaticKeyMatchesTheInitiators(t *testing.T) {
	responderPrivate, err := GeneratePrivateKey()
	require.NoError(t, err)
	responderPublic, err := responderPrivate.PublicKey()
	require.NoError(t, err)

	// Both sides start from the same transcript and reach the same point by
	// running Curve25519 with the halves of the key pairs they each hold.
	initiatorState := NewHandshakeState(responderPublic)
	var message HandshakeInitiation
	ephemeralPrivate, err := initiatorState.setInitiationEphemeral(&message)
	require.NoError(t, err)

	responderState := NewHandshakeState(responderPublic)
	responderState.consumeInitiationEphemeral(message)

	initiatorKey, err := initiatorState.deriveInitiationStaticEncryptionKey(
		ephemeralPrivate,
		responderPublic,
	)
	require.NoError(t, err)

	responderKey, err := responderState.consumeInitiationStaticDecryptionKey(
		responderPrivate,
		message,
	)
	require.NoError(t, err)

	require.Equal(t, initiatorKey, responderKey)
	require.Equal(t, initiatorState, responderState)
}

func TestConsumeInitiationLearnsTheInitiatorsIdentity(t *testing.T) {
	initiatorPrivate, err := GeneratePrivateKey()
	require.NoError(t, err)
	initiatorPublic, err := initiatorPrivate.PublicKey()
	require.NoError(t, err)
	responderPrivate, err := GeneratePrivateKey()
	require.NoError(t, err)
	responderPublic, err := responderPrivate.PublicKey()
	require.NoError(t, err)

	message, _, _, err := CreateInitiation(initiatorPrivate, responderPublic)
	require.NoError(t, err)

	_, got, _, _, err := ConsumeInitiation(responderPrivate, message.MarshalBinary())

	require.NoError(t, err)
	require.Equal(t, initiatorPublic, got)
}

func TestConsumeInitiationRejectsTamperedStaticField(t *testing.T) {
	initiatorPrivate, err := GeneratePrivateKey()
	require.NoError(t, err)
	responderPrivate, err := GeneratePrivateKey()
	require.NoError(t, err)
	responderPublic, err := responderPrivate.PublicKey()
	require.NoError(t, err)

	message, _, _, err := CreateInitiation(initiatorPrivate, responderPublic)
	require.NoError(t, err)

	// MAC1 covers the static field, so it has to be recomputed after the edit.
	// Otherwise the message would be rejected earlier and the AEAD tag would
	// never be reached.
	message.EncryptedStatic[0] ^= 0x01
	setInitiationMAC1(&message, responderPublic)

	_, _, _, _, err = ConsumeInitiation(responderPrivate, message.MarshalBinary())

	require.ErrorContains(t, err, "decrypt handshake initiation static key")
}

func TestConsumeInitiationTimestampKeyMatchesTheInitiators(t *testing.T) {
	initiatorPrivate, err := GeneratePrivateKey()
	require.NoError(t, err)
	initiatorPublic, err := initiatorPrivate.PublicKey()
	require.NoError(t, err)
	responderPrivate, err := GeneratePrivateKey()
	require.NoError(t, err)
	responderPublic, err := responderPrivate.PublicKey()
	require.NoError(t, err)

	// The transcript up to this point does not matter for the comparison, only
	// that both sides share it, so an empty state is enough.
	initiatorState := NewHandshakeState(responderPublic)
	responderState := NewHandshakeState(responderPublic)

	initiatorKey, err := initiatorState.deriveInitiationTimestampEncryptionKey(
		initiatorPrivate,
		responderPublic,
	)
	require.NoError(t, err)

	responderKey, err := responderState.consumeInitiationTimestampDecryptionKey(
		responderPrivate,
		initiatorPublic,
	)
	require.NoError(t, err)

	require.Equal(t, initiatorKey, responderKey)
	require.Equal(t, initiatorState, responderState)
}

func TestConsumeInitiationRejectsTamperedTimestampField(t *testing.T) {
	initiatorPrivate, err := GeneratePrivateKey()
	require.NoError(t, err)
	responderPrivate, err := GeneratePrivateKey()
	require.NoError(t, err)
	responderPublic, err := responderPrivate.PublicKey()
	require.NoError(t, err)

	message, _, _, err := CreateInitiation(initiatorPrivate, responderPublic)
	require.NoError(t, err)

	message.EncryptedTimestamp[0] ^= 0x01
	setInitiationMAC1(&message, responderPublic)

	_, _, _, _, err = ConsumeInitiation(responderPrivate, message.MarshalBinary())

	require.ErrorContains(t, err, "decrypt handshake initiation timestamp")
}

func TestConsumeInitiationRejectsAnotherInitiator(t *testing.T) {
	initiatorPrivate, err := GeneratePrivateKey()
	require.NoError(t, err)
	responderPrivate, err := GeneratePrivateKey()
	require.NoError(t, err)
	responderPublic, err := responderPrivate.PublicKey()
	require.NoError(t, err)

	message, _, _, err := CreateInitiation(initiatorPrivate, responderPublic)
	require.NoError(t, err)

	// An attacker who knows the responder's public key can reach the static
	// field, but claiming somebody else's identity fails at the timestamp tag,
	// because that key comes from the static-static ECDH.
	impostorPrivate, err := GeneratePrivateKey()
	require.NoError(t, err)
	impostorPublic, err := impostorPrivate.PublicKey()
	require.NoError(t, err)

	state := NewHandshakeState(responderPublic)
	state.consumeInitiationEphemeral(message)
	staticKey, err := state.consumeInitiationStaticDecryptionKey(responderPrivate, message)
	require.NoError(t, err)

	aead, err := chacha20poly1305.New(staticKey[:])
	require.NoError(t, err)
	var nonce [chacha20poly1305.NonceSize]byte
	copy(message.EncryptedStatic[:], aead.Seal(nil, nonce[:], impostorPublic[:], state.Hash[:]))
	setInitiationMAC1(&message, responderPublic)

	_, _, _, _, err = ConsumeInitiation(responderPrivate, message.MarshalBinary())

	require.ErrorContains(t, err, "decrypt handshake initiation timestamp")
}

func TestCreateInitiationAndConsumeInitiationAgree(t *testing.T) {
	initiatorPrivate, err := GeneratePrivateKey()
	require.NoError(t, err)
	initiatorPublic, err := initiatorPrivate.PublicKey()
	require.NoError(t, err)
	responderPrivate, err := GeneratePrivateKey()
	require.NoError(t, err)
	responderPublic, err := responderPrivate.PublicKey()
	require.NoError(t, err)

	before := newTAI64NTimestamp(time.Now())
	message, _, initiatorState, err := CreateInitiation(initiatorPrivate, responderPublic)
	require.NoError(t, err)
	after := newTAI64NTimestamp(time.Now())

	gotMessage, gotStatic, gotTimestamp, responderState, err := ConsumeInitiation(
		responderPrivate,
		message.MarshalBinary(),
	)

	require.NoError(t, err)
	require.Equal(t, message, gotMessage)
	require.Equal(t, initiatorPublic, gotStatic)
	require.GreaterOrEqual(t, string(gotTimestamp[:]), string(before[:]))
	require.LessOrEqual(t, string(gotTimestamp[:]), string(after[:]))

	// Both sides end the first message with an identical transcript. This is
	// what the handshake response will be built on.
	require.Equal(t, initiatorState.Hash, responderState.Hash)
	require.Equal(t, initiatorState.ChainingKey, responderState.ChainingKey)
	require.True(t, initiatorState.IsInitiator)
	require.False(t, responderState.IsInitiator)
}
