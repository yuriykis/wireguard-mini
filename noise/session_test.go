package noise

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSealCanBeDecryptedWithSendKey(t *testing.T) {
	sendKey := [HashSize]byte{1}
	var sender Session
	sender.SetKeys(TransportKeys{
		Send:    sendKey,
		Receive: [HashSize]byte{2},
	})
	packet := []byte("ping packet")

	sealed, err := sender.Seal(packet)
	require.NoError(t, err)

	message, err := ParseTransportData(sealed)
	require.NoError(t, err)

	decrypted, err := DecryptTransportData(sendKey, message.Counter, message.EncryptedPacket)
	require.NoError(t, err)
	require.Equal(t, packet, decrypted)
}

func TestOpenDecryptsPacketSealedByPeer(t *testing.T) {
	var sender, receiver Session
	sender.SetKeys(TransportKeys{
		Send:    [HashSize]byte{1},
		Receive: [HashSize]byte{2},
	})
	receiver.SetKeys(TransportKeys{
		Send:    [HashSize]byte{2},
		Receive: [HashSize]byte{1},
	})
	packet := []byte("ping packet")

	sealed, err := sender.Seal(packet)
	require.NoError(t, err)

	opened, err := receiver.Open(sealed)
	require.NoError(t, err)
	require.Equal(t, packet, opened)
}
