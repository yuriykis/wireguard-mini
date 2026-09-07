package noise

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

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

func TestSetResponseMAC1(t *testing.T) {
	initiatorStaticPrivate, err := GeneratePrivateKey()
	require.NoError(t, err)
	initiatorStaticPublic, err := initiatorStaticPrivate.PublicKey()
	require.NoError(t, err)
	message := HandshakeResponse{SenderIndex: 42, ReceiverIndex: 7}

	setResponseMAC1(&message, initiatorStaticPublic)

	data := message.MarshalBinary()
	expected := calculateMAC1(deriveMAC1Key(initiatorStaticPublic), data[:responseMAC1Offset])
	require.Equal(t, expected, message.MAC1)
	require.Equal(t, expected[:], data[responseMAC1Offset:responseMAC2Offset])

	// A host that does not know the initiator's static public key cannot
	// produce this value, which is what lets the initiator drop foreign
	// packets before doing any real cryptography.
	strangerPrivate, err := GeneratePrivateKey()
	require.NoError(t, err)
	strangerPublic, err := strangerPrivate.PublicKey()
	require.NoError(t, err)
	strangerMAC1 := calculateMAC1(deriveMAC1Key(strangerPublic), data[:responseMAC1Offset])
	require.NotEqual(t, strangerMAC1, message.MAC1)
}

func TestSetResponseMAC2(t *testing.T) {
	message := HandshakeResponse{MAC2: [16]byte{1, 2, 3}}

	setResponseMAC2(&message)

	require.Equal(t, [16]byte{}, message.MAC2)
}
