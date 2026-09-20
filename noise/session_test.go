package noise

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSealCanBeDecryptedWithSendKey(t *testing.T) {
	sender := Session{Keys: TransportKeys{Send: [HashSize]byte{1}, Receive: [HashSize]byte{2}}}
	packet := []byte("ping packet")

	encrypted, err := sender.Seal(packet)
	require.NoError(t, err)

	decrypted, err := DecryptTransportData(sender.Keys.Send, 0, encrypted)
	require.NoError(t, err)
	require.Equal(t, packet, decrypted)
}
