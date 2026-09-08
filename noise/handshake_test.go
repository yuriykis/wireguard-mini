package noise

import (
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/chacha20poly1305"
)

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
