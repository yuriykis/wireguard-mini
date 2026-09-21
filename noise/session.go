package noise

// Session holds everything one peer needs to exchange transport data after a handshake.
type Session struct {
	Keys        TransportKeys
	LocalIndex  uint32
	RemoteIndex uint32
	sendCounter uint64
	replay      ReplayWindow
}

// Seal encrypts a packet read from TUN with the session's send key.
func (session *Session) Seal(packet []byte) ([]byte, error) {
	encrypted, err := EncryptTransportData(session.Keys.Send, session.sendCounter, packet)
	session.sendCounter++
	return encrypted, err
}
