package noise

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/chacha20poly1305"
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

func TestDeriveMAC1Key(t *testing.T) {
	key := deriveMAC1Key(PublicKey{9})

	require.Equal(t,
		"a58c8d76d9b6b46b858c5beeb096da9a6dbae987b17cd68b373a350547873779",
		hex.EncodeToString(key[:]),
	)
}

func TestCalculateMAC1(t *testing.T) {
	mac1Key := deriveMAC1Key(PublicKey{9})

	mac1 := calculateMAC1(mac1Key, []byte{1, 2, 3})

	require.Equal(t,
		"e26e552b977dff4253651d289a979a98",
		hex.EncodeToString(mac1[:]),
	)
}

func TestSetInitiationMAC1(t *testing.T) {
	message := HandshakeInitiation{
		SenderIndex:          42,
		UnencryptedEphemeral: [32]byte{1},
		EncryptedStatic:      [48]byte{2},
		EncryptedTimestamp:   [28]byte{3},
	}
	responderPublicKey := PublicKey{9}
	dataBeforeMAC1 := message.MarshalBinary()[:mac1Offset]
	expectedMAC1 := calculateMAC1(
		deriveMAC1Key(responderPublicKey),
		dataBeforeMAC1,
	)
	expectedMessage := message
	expectedMessage.MAC1 = expectedMAC1

	setInitiationMAC1(&message, responderPublicKey)

	require.Equal(t, expectedMessage, message)
	require.NotEqual(t, [16]byte{}, message.MAC1)
}

func TestGenerateSenderIndexIsRandom(t *testing.T) {
	first, err := generateSenderIndex()
	require.NoError(t, err)
	second, err := generateSenderIndex()
	require.NoError(t, err)

	require.NotEqual(t, first, second)
}

func TestSetInitiationMAC2IsZeroWithoutCookie(t *testing.T) {
	message := HandshakeInitiation{
		SenderIndex: 42,
		MAC1:        [16]byte{7},
		MAC2:        [16]byte{1, 2, 3},
	}
	expectedMessage := message
	expectedMessage.MAC2 = [16]byte{}

	setInitiationMAC2(&message)

	require.Equal(t, expectedMessage, message)
}

func TestCreateInitiationFillsEveryField(t *testing.T) {
	initiatorPrivate, err := GeneratePrivateKey()
	require.NoError(t, err)
	responderPrivate, err := GeneratePrivateKey()
	require.NoError(t, err)
	responderPublic, err := responderPrivate.PublicKey()
	require.NoError(t, err)

	message, _, err := CreateInitiation(initiatorPrivate, responderPublic)
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

	first, firstState, err := CreateInitiation(initiatorPrivate, responderPublic)
	require.NoError(t, err)
	second, secondState, err := CreateInitiation(initiatorPrivate, responderPublic)
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
	message, initiatorState, err := CreateInitiation(initiatorPrivate, responderPublic)
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
