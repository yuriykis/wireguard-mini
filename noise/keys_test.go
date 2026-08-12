package noise

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGeneratePrivateKeyClampsScalar(t *testing.T) {
	key, err := GeneratePrivateKey()

	require.NoError(t, err)
	require.Zero(t, key[0]&0b00000111)
	require.Zero(t, key[31]&0b10000000)
	require.Equal(t, byte(0b01000000), key[31]&0b01000000)
}

func TestSharedSecretIsTheSameForBothPeers(t *testing.T) {
	alicePrivate, err := GeneratePrivateKey()
	require.NoError(t, err)
	bobPrivate, err := GeneratePrivateKey()
	require.NoError(t, err)

	alicePublic, err := alicePrivate.PublicKey()
	require.NoError(t, err)
	bobPublic, err := bobPrivate.PublicKey()
	require.NoError(t, err)

	aliceShared, err := alicePrivate.SharedSecret(bobPublic)
	require.NoError(t, err)
	bobShared, err := bobPrivate.SharedSecret(alicePublic)
	require.NoError(t, err)

	require.Equal(t, aliceShared, bobShared)
	require.NotEqual(t, [KeySize]byte{}, aliceShared)
}

func TestSharedSecretRejectsLowOrderPublicKey(t *testing.T) {
	privateKey, err := GeneratePrivateKey()
	require.NoError(t, err)

	_, err = privateKey.SharedSecret(PublicKey{})

	require.ErrorContains(t, err, "derive shared secret")
}
