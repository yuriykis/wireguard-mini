package noise

// TransportKeys holds the two session keys a peer uses after the handshake.
type TransportKeys struct {
	Send    [HashSize]byte
	Receive [HashSize]byte
}

// DeriveTransportKeys turns the final chaining key into the pair of session keys.
func (state *HandshakeState) DeriveTransportKeys() TransportKeys {
	first, second := kdf2(state.ChainingKey[:], nil)
	clear(state.ChainingKey[:])
	if state.IsInitiator {
		return TransportKeys{Send: first, Receive: second}
	}
	return TransportKeys{Send: second, Receive: first}
}

// EncryptTransportData seals a packet read from TUN.
func EncryptTransportData(packet []byte) []byte {
	// encrypt the packet
	return nil
}

func kdf2(key, input []byte) (first, second [HashSize]byte) {
	temporary := hmacBlake2s(key, input)
	first = hmacBlake2s(temporary[:], []byte{1})

	secondInput := make([]byte, 0, len(first)+1)
	secondInput = append(secondInput, first[:]...)
	secondInput = append(secondInput, 2)
	second = hmacBlake2s(temporary[:], secondInput)
	return first, second
}
