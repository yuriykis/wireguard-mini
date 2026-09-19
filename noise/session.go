package noise

// Session holds everything one peer needs to exchange transport data after a handshake.
type Session struct {
	Keys        TransportKeys
	LocalIndex  uint32
	RemoteIndex uint32
	sendCounter uint64
	replay      ReplayWindow
}
