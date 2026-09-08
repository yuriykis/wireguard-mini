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
	require.Equal(t, initiatorState, state)
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
	require.Equal(t, initiatorState, responderState)
}

func TestSetResponseEphemeral(t *testing.T) {
	state := NewHandshakeState(PublicKey{9})
	expectedState := state
	message := HandshakeResponse{SenderIndex: 42, ReceiverIndex: 7}

	ephemeralPrivate, err := state.setResponseEphemeral(&message)

	require.NoError(t, err)
	ephemeralPublic, err := ephemeralPrivate.PublicKey()
	require.NoError(t, err)
	require.Equal(t, ephemeralPublic[:], message.UnencryptedEphemeral[:])

	expectedState.mixHash(message.UnencryptedEphemeral[:])
	expectedState.mixKey(message.UnencryptedEphemeral[:])
	require.Equal(t, expectedState.Hash, state.Hash)
	require.Equal(t, expectedState.ChainingKey, state.ChainingKey)
	require.Equal(t, uint32(42), message.SenderIndex)
	require.Equal(t, uint32(7), message.ReceiverIndex)
	require.Equal(t, [16]byte{}, message.EncryptedNothing)
}

func TestMixResponseEphemeralSharedSecret(t *testing.T) {
	initiatorEphemeralPrivate, err := GeneratePrivateKey()
	require.NoError(t, err)
	initiatorEphemeralPublic, err := initiatorEphemeralPrivate.PublicKey()
	require.NoError(t, err)

	state := NewHandshakeState(PublicKey{9})
	message := HandshakeResponse{}
	responderEphemeralPrivate, err := state.setResponseEphemeral(&message)
	require.NoError(t, err)
	hashBefore := state.Hash
	expectedState := state

	err = state.mixResponseEphemeralSharedSecret(
		responderEphemeralPrivate,
		initiatorEphemeralPublic,
	)

	require.NoError(t, err)
	// The initiator computes the same secret from the other side of the
	// exchange, which is what makes both transcripts agree.
	sharedSecret, err := initiatorEphemeralPrivate.SharedSecret(
		PublicKey(message.UnencryptedEphemeral),
	)
	require.NoError(t, err)
	expectedState.mixKey(sharedSecret[:])
	require.Equal(t, expectedState.ChainingKey, state.ChainingKey)
	// This step feeds the chaining key only; the transcript hash is untouched.
	require.Equal(t, hashBefore, state.Hash)
}

func TestMixResponseStaticSharedSecret(t *testing.T) {
	initiatorStaticPrivate, err := GeneratePrivateKey()
	require.NoError(t, err)
	initiatorStaticPublic, err := initiatorStaticPrivate.PublicKey()
	require.NoError(t, err)

	state := NewHandshakeState(PublicKey{9})
	message := HandshakeResponse{}
	responderEphemeralPrivate, err := state.setResponseEphemeral(&message)
	require.NoError(t, err)
	hashBefore := state.Hash
	expectedState := state

	err = state.mixResponseStaticSharedSecret(
		responderEphemeralPrivate,
		initiatorStaticPublic,
	)

	require.NoError(t, err)
	// The initiator reaches the same secret with its static private key and
	// the responder's ephemeral public key taken from the response.
	sharedSecret, err := initiatorStaticPrivate.SharedSecret(
		PublicKey(message.UnencryptedEphemeral),
	)
	require.NoError(t, err)
	expectedState.mixKey(sharedSecret[:])
	require.Equal(t, expectedState.ChainingKey, state.ChainingKey)
	require.Equal(t, hashBefore, state.Hash)
}

func TestMixResponseStaticSharedSecretRejectsWrongIdentity(t *testing.T) {
	initiatorStaticPrivate, err := GeneratePrivateKey()
	require.NoError(t, err)
	initiatorStaticPublic, err := initiatorStaticPrivate.PublicKey()
	require.NoError(t, err)
	strangerStaticPrivate, err := GeneratePrivateKey()
	require.NoError(t, err)

	state := NewHandshakeState(PublicKey{9})
	message := HandshakeResponse{}
	responderEphemeralPrivate, err := state.setResponseEphemeral(&message)
	require.NoError(t, err)
	expectedState := state

	require.NoError(t, state.mixResponseStaticSharedSecret(
		responderEphemeralPrivate,
		initiatorStaticPublic,
	))

	// Anybody else derives a different chaining key and therefore a different
	// transcript, which is what stops a third party from finishing this
	// handshake.
	strangerSecret, err := strangerStaticPrivate.SharedSecret(
		PublicKey(message.UnencryptedEphemeral),
	)
	require.NoError(t, err)
	expectedState.mixKey(strangerSecret[:])
	require.NotEqual(t, expectedState.ChainingKey, state.ChainingKey)
}

func TestEncryptResponseNothing(t *testing.T) {
	state := NewHandshakeState(PublicKey{9})
	var presharedKey [PresharedKeySize]byte
	encryptionKey := state.mixKeyHashAndGetEncryptionKey(presharedKey[:])
	hashBefore := state.Hash
	chainingKeyBefore := state.ChainingKey
	message := HandshakeResponse{}

	err := state.encryptResponseNothing(&message, encryptionKey)

	require.NoError(t, err)
	// The other side opens the tag with the same key and the hash as it stood
	// before this step, and gets an empty plaintext back.
	aead, err := chacha20poly1305.New(encryptionKey[:])
	require.NoError(t, err)
	var nonce [chacha20poly1305.NonceSize]byte
	plaintext, err := aead.Open(nil, nonce[:], message.EncryptedNothing[:], hashBefore[:])
	require.NoError(t, err)
	require.Empty(t, plaintext)

	expectedState := HandshakeState{Hash: hashBefore}
	expectedState.mixHash(message.EncryptedNothing[:])
	require.Equal(t, expectedState.Hash, state.Hash)
	// Encrypting does not feed the chaining key; only the hash moves on.
	require.Equal(t, chainingKeyBefore, state.ChainingKey)
}

func TestEncryptResponseNothingRejectsADifferentTranscript(t *testing.T) {
	state := NewHandshakeState(PublicKey{9})
	var presharedKey [PresharedKeySize]byte
	encryptionKey := state.mixKeyHashAndGetEncryptionKey(presharedKey[:])
	message := HandshakeResponse{}
	require.NoError(t, state.encryptResponseNothing(&message, encryptionKey))

	// A receiver whose transcript differs by a single byte cannot open the
	// tag, which is exactly how the response authenticates the responder.
	aead, err := chacha20poly1305.New(encryptionKey[:])
	require.NoError(t, err)
	var nonce [chacha20poly1305.NonceSize]byte
	wrongHash := NewHandshakeState(PublicKey{10}).Hash
	_, err = aead.Open(nil, nonce[:], message.EncryptedNothing[:], wrongHash[:])
	require.Error(t, err)
}

func TestCreateResponseProducesAWellFormedMessage(t *testing.T) {
	initiatorStaticPrivate, err := GeneratePrivateKey()
	require.NoError(t, err)
	initiatorStaticPublic, err := initiatorStaticPrivate.PublicKey()
	require.NoError(t, err)
	responderStaticPrivate, err := GeneratePrivateKey()
	require.NoError(t, err)
	responderStaticPublic, err := responderStaticPrivate.PublicKey()
	require.NoError(t, err)

	initiation, _, _, err := CreateInitiation(initiatorStaticPrivate, responderStaticPublic)
	require.NoError(t, err)
	_, learnedInitiatorPublic, _, stateAfterInitiation, err := ConsumeInitiation(
		responderStaticPrivate,
		initiation.MarshalBinary(),
	)
	require.NoError(t, err)
	require.Equal(t, initiatorStaticPublic, learnedInitiatorPublic)

	response, stateAfterResponse, err := CreateResponse(
		learnedInitiatorPublic,
		initiation,
		stateAfterInitiation,
	)

	require.NoError(t, err)
	parsed, err := ParseHandshakeResponse(response.MarshalBinary())
	require.NoError(t, err)
	require.Equal(t, response, parsed)
	require.Equal(t, initiation.SenderIndex, response.ReceiverIndex)
	require.NotZero(t, response.SenderIndex)
	require.NotEqual(t, [32]byte{}, response.UnencryptedEphemeral)
	require.NotEqual(t, [16]byte{}, response.EncryptedNothing)
	require.Equal(t, [16]byte{}, response.MAC2)
	// Building the response continues the transcript, so neither value can be
	// left where consuming the initiation stopped.
	require.NotEqual(t, stateAfterInitiation.Hash, stateAfterResponse.Hash)
	require.NotEqual(t, stateAfterInitiation.ChainingKey, stateAfterResponse.ChainingKey)
}

func TestCreateResponseUsesFreshEphemeralEveryTime(t *testing.T) {
	initiatorStaticPrivate, err := GeneratePrivateKey()
	require.NoError(t, err)
	responderStaticPrivate, err := GeneratePrivateKey()
	require.NoError(t, err)
	responderStaticPublic, err := responderStaticPrivate.PublicKey()
	require.NoError(t, err)

	initiation, _, _, err := CreateInitiation(initiatorStaticPrivate, responderStaticPublic)
	require.NoError(t, err)
	_, initiatorStaticPublic, _, state, err := ConsumeInitiation(
		responderStaticPrivate,
		initiation.MarshalBinary(),
	)
	require.NoError(t, err)

	first, firstState, err := CreateResponse(initiatorStaticPublic, initiation, state)
	require.NoError(t, err)
	second, secondState, err := CreateResponse(initiatorStaticPublic, initiation, state)
	require.NoError(t, err)

	require.NotEqual(t, first.UnencryptedEphemeral, second.UnencryptedEphemeral)
	require.NotEqual(t, first.SenderIndex, second.SenderIndex)
	require.NotEqual(t, first.EncryptedNothing, second.EncryptedNothing)
	require.NotEqual(t, firstState.ChainingKey, secondState.ChainingKey)
}

func TestConsumeResponseRejectsMalformedMessage(t *testing.T) {
	initiatorPrivate, err := GeneratePrivateKey()
	require.NoError(t, err)
	initiatorEphemeralPrivate, err := GeneratePrivateKey()
	require.NoError(t, err)

	valid := testHandshakeResponse().MarshalBinary()

	tests := []struct {
		name    string
		data    []byte
		wantErr string
	}{
		{name: "too short", data: valid[:HandshakeResponseSize-1], wantErr: "invalid handshake response length"},
		{name: "wrong type", data: withByte(valid, 0, 1), wantErr: "invalid handshake response type"},
		{name: "non-zero reserved byte", data: withByte(valid, 2, 1), wantErr: "reserved bytes must be zero"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := ConsumeResponse(initiatorPrivate, initiatorEphemeralPrivate, tt.data, HandshakeState{})
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestConsumeResponseRejectsWrongMAC1(t *testing.T) {
	initiatorStaticPrivate, err := GeneratePrivateKey()
	require.NoError(t, err)
	initiatorEphemeralPrivate, err := GeneratePrivateKey()
	require.NoError(t, err)
	responderStaticPrivate, err := GeneratePrivateKey()
	require.NoError(t, err)
	responderStaticPublic, err := responderStaticPrivate.PublicKey()
	require.NoError(t, err)

	initiation, _, _, err := CreateInitiation(initiatorStaticPrivate, responderStaticPublic)
	require.NoError(t, err)
	_, initiatorStaticPublic, _, stateAfterInitiation, err := ConsumeInitiation(
		responderStaticPrivate,
		initiation.MarshalBinary(),
	)
	require.NoError(t, err)

	response, _, err := CreateResponse(initiatorStaticPublic, initiation, stateAfterInitiation)
	require.NoError(t, err)

	t.Run("tampered mac1", func(t *testing.T) {
		data := response.MarshalBinary()
		data[responseMAC1Offset] ^= 0x01

		_, _, err := ConsumeResponse(initiatorStaticPrivate, initiatorEphemeralPrivate, data, HandshakeState{})

		require.ErrorContains(t, err, "MAC1 mismatch")
	})

	t.Run("tampered payload", func(t *testing.T) {
		data := response.MarshalBinary()
		data[responseEphemeralOffset] ^= 0x01

		_, _, err := ConsumeResponse(initiatorStaticPrivate, initiatorEphemeralPrivate, data, HandshakeState{})

		require.ErrorContains(t, err, "MAC1 mismatch")
	})

	t.Run("addressed to another initiator", func(t *testing.T) {
		otherPrivate, err := GeneratePrivateKey()
		require.NoError(t, err)

		_, _, err = ConsumeResponse(otherPrivate, initiatorEphemeralPrivate, response.MarshalBinary(), HandshakeState{})

		require.ErrorContains(t, err, "MAC1 mismatch")
	})
}

func TestConsumeResponseEphemeralMirrorsSetResponseEphemeral(t *testing.T) {
	responderStaticPrivate, err := GeneratePrivateKey()
	require.NoError(t, err)
	responderStaticPublic, err := responderStaticPrivate.PublicKey()
	require.NoError(t, err)

	// Both sides start from the same transcript and absorb the same ephemeral
	// public key, one while writing it, the other while reading it.
	responderState := NewHandshakeState(responderStaticPublic)
	initiatorState := responderState

	var message HandshakeResponse
	_, err = responderState.setResponseEphemeral(&message)
	require.NoError(t, err)

	initiatorState.consumeResponseEphemeral(message)

	require.Equal(t, responderState, initiatorState)
	require.NotEqual(t, NewHandshakeState(responderStaticPublic), initiatorState)
}

func TestCreateResponseAndConsumeResponseAgree(t *testing.T) {
	initiatorStaticPrivate, err := GeneratePrivateKey()
	require.NoError(t, err)
	responderStaticPrivate, err := GeneratePrivateKey()
	require.NoError(t, err)
	responderStaticPublic, err := responderStaticPrivate.PublicKey()
	require.NoError(t, err)

	initiation, initiatorEphemeralPrivate, stateAfterInitiation, err := CreateInitiation(
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

	got, initiatorState, err := ConsumeResponse(
		initiatorStaticPrivate,
		initiatorEphemeralPrivate,
		response.MarshalBinary(),
		stateAfterInitiation,
	)

	require.NoError(t, err)
	require.Equal(t, response, got)
	require.Equal(t, responderState, initiatorState)
}

func TestConsumeResponseRejectsATamperedTagOverAValidMAC1(t *testing.T) {
	initiatorStaticPrivate, err := GeneratePrivateKey()
	require.NoError(t, err)
	responderStaticPrivate, err := GeneratePrivateKey()
	require.NoError(t, err)
	responderStaticPublic, err := responderStaticPrivate.PublicKey()
	require.NoError(t, err)

	initiation, initiatorEphemeralPrivate, stateAfterInitiation, err := CreateInitiation(
		initiatorStaticPrivate,
		responderStaticPublic,
	)
	require.NoError(t, err)

	_, initiatorStaticPublic, _, responderStateAfterInitiation, err := ConsumeInitiation(
		responderStaticPrivate,
		initiation.MarshalBinary(),
	)
	require.NoError(t, err)

	response, _, err := CreateResponse(
		initiatorStaticPublic,
		initiation,
		responderStateAfterInitiation,
	)
	require.NoError(t, err)

	// MAC1 is recomputed after the change, so the message survives the cheap
	// check and only the tag can still tell that it was touched.
	response.EncryptedNothing[0] ^= 1
	setResponseMAC1(&response, initiatorStaticPublic)

	_, _, err = ConsumeResponse(
		initiatorStaticPrivate,
		initiatorEphemeralPrivate,
		response.MarshalBinary(),
		stateAfterInitiation,
	)

	require.Error(t, err)
}

func TestGenerateSenderIndexIsRandom(t *testing.T) {
	first, err := generateSenderIndex()
	require.NoError(t, err)
	second, err := generateSenderIndex()
	require.NoError(t, err)

	require.NotEqual(t, first, second)
}
