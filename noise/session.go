package noise

import (
	"errors"
	"sync"
)

// Session holds everything one peer needs to exchange transport data after a handshake.
type Session struct {
	mu          sync.Mutex
	keys        TransportKeys
	LocalIndex  uint32
	RemoteIndex uint32
	sendCounter uint64
	replay      ReplayWindow
}

// SetKeys starts a fresh session under new transport keys.
func (session *Session) SetKeys(keys TransportKeys) {
	session.mu.Lock()
	defer session.mu.Unlock()
	session.keys = keys
	session.sendCounter = 0
	session.replay = ReplayWindow{}
}

// Seal encrypts a packet read from TUN into a transport data message.
func (session *Session) Seal(packet []byte) ([]byte, error) {
	session.mu.Lock()
	defer session.mu.Unlock()

	counter := session.sendCounter
	session.sendCounter++

	encrypted, err := EncryptTransportData(session.keys.Send, counter, packet)
	if err != nil {
		return nil, err
	}
	return TransportData{
		ReceiverIndex:   session.RemoteIndex,
		Counter:         counter,
		EncryptedPacket: encrypted,
	}.MarshalBinary(), nil
}

// Open decrypts a transport data message received from UDP into a packet for TUN.
func (session *Session) Open(data []byte) ([]byte, error) {
	session.mu.Lock()
	defer session.mu.Unlock()

	message, err := ParseTransportData(data)
	if err != nil {
		return nil, err
	}

	packet, err := DecryptTransportData(session.keys.Receive, message.Counter, message.EncryptedPacket)
	if err != nil {
		return nil, err
	}
	if !session.replay.CheckCounter(message.Counter) {
		return nil, errors.New("transport data counter already used or too old")
	}
	return packet, nil
}
