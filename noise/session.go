package noise

// Session holds everything one peer needs to exchange transport data after a handshake.
type Session struct {
	Keys        TransportKeys
	LocalIndex  uint32
	RemoteIndex uint32
	sendCounter uint64
	replay      ReplayWindow
}

// Seal encrypts a packet read from TUN into a transport data message.
func (session *Session) Seal(packet []byte) ([]byte, error) {
	counter := session.sendCounter
	session.sendCounter++

	encrypted, err := EncryptTransportData(session.Keys.Send, counter, packet)
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
	message, err := ParseTransportData(data)
	if err != nil {
		return nil, err
	}
	return DecryptTransportData(session.Keys.Receive, message.Counter, message.EncryptedPacket)
}
