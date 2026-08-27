package noise

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHandshakeResponseMarshalBinary(t *testing.T) {
	message := testHandshakeResponse()

	data := message.MarshalBinary()

	require.Len(t, data, HandshakeResponseSize)
	require.Equal(t, byte(2), data[0])
	require.Equal(t, []byte{0, 0, 0}, data[1:4])
	require.Equal(t, []byte{0x04, 0x03, 0x02, 0x01}, data[4:8])
	require.Equal(t, []byte{0x08, 0x07, 0x06, 0x05}, data[8:12])
	require.Equal(t, message.UnencryptedEphemeral[:], data[12:44])
	require.Equal(t, message.EncryptedNothing[:], data[44:60])
	require.Equal(t, message.MAC1[:], data[60:76])
	require.Equal(t, message.MAC2[:], data[76:92])
}

func TestHandshakeResponseRoundTrip(t *testing.T) {
	want := testHandshakeResponse()

	got, err := ParseHandshakeResponse(want.MarshalBinary())

	require.NoError(t, err)
	require.Equal(t, want, got)
}

func TestParseHandshakeResponseRejectsInvalidMessage(t *testing.T) {
	valid := testHandshakeResponse().MarshalBinary()

	tests := []struct {
		name    string
		data    []byte
		wantErr string
	}{
		{name: "too short", data: valid[:HandshakeResponseSize-1], wantErr: "invalid handshake response length"},
		{name: "too long", data: append(append([]byte(nil), valid...), 0), wantErr: "invalid handshake response length"},
		{name: "wrong type", data: withByte(valid, 0, 1), wantErr: "invalid handshake response type"},
		{name: "non-zero reserved byte", data: withByte(valid, 2, 1), wantErr: "reserved bytes must be zero"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseHandshakeResponse(tt.data)
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestHandshakeInitiationMarshalBinary(t *testing.T) {
	message := testHandshakeInitiation()

	data := message.MarshalBinary()

	require.Len(t, data, HandshakeInitiationSize)
	require.Equal(t, byte(1), data[0])
	require.Equal(t, []byte{0, 0, 0}, data[1:4])
	require.Equal(t, []byte{0x04, 0x03, 0x02, 0x01}, data[4:8])
	require.Equal(t, message.UnencryptedEphemeral[:], data[8:40])
	require.Equal(t, message.EncryptedStatic[:], data[40:88])
	require.Equal(t, message.EncryptedTimestamp[:], data[88:116])
	require.Equal(t, message.MAC1[:], data[116:132])
	require.Equal(t, message.MAC2[:], data[132:148])
}

func TestHandshakeInitiationRoundTrip(t *testing.T) {
	want := testHandshakeInitiation()

	got, err := ParseHandshakeInitiation(want.MarshalBinary())

	require.NoError(t, err)
	require.Equal(t, want, got)
}

func TestParseHandshakeInitiationRejectsInvalidMessage(t *testing.T) {
	valid := testHandshakeInitiation().MarshalBinary()

	tests := []struct {
		name    string
		data    []byte
		wantErr string
	}{
		{name: "too short", data: valid[:HandshakeInitiationSize-1], wantErr: "invalid handshake initiation length"},
		{name: "too long", data: append(append([]byte(nil), valid...), 0), wantErr: "invalid handshake initiation length"},
		{name: "wrong type", data: withByte(valid, 0, 2), wantErr: "invalid handshake initiation type"},
		{name: "non-zero reserved byte", data: withByte(valid, 2, 1), wantErr: "reserved bytes must be zero"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseHandshakeInitiation(tt.data)
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func testHandshakeInitiation() HandshakeInitiation {
	var message HandshakeInitiation
	message.SenderIndex = 0x01020304
	fill(message.UnencryptedEphemeral[:], 0x10)
	fill(message.EncryptedStatic[:], 0x40)
	fill(message.EncryptedTimestamp[:], 0x70)
	fill(message.MAC1[:], 0x90)
	fill(message.MAC2[:], 0xa0)
	return message
}

func testHandshakeResponse() HandshakeResponse {
	var message HandshakeResponse
	message.SenderIndex = 0x01020304
	message.ReceiverIndex = 0x05060708
	fill(message.UnencryptedEphemeral[:], 0x10)
	fill(message.EncryptedNothing[:], 0x40)
	fill(message.MAC1[:], 0x60)
	fill(message.MAC2[:], 0x70)
	return message
}

func fill(data []byte, start byte) {
	for index := range data {
		data[index] = start + byte(index)
	}
}

func withByte(data []byte, index int, value byte) []byte {
	result := append([]byte(nil), data...)
	result[index] = value
	return result
}
