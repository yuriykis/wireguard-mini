package noise

// TransportKeys holds the two session keys a peer uses after the handshake.
type TransportKeys struct {
	Send    [HashSize]byte
	Receive [HashSize]byte
}

// DeriveTransportKeys turns the final chaining key into the pair of session keys.
func (state *HandshakeState) DeriveTransportKeys() TransportKeys {
	// TODO: run the KDF over the chaining key with an empty input
	// TODO: take the first output as one key and the second as the other
	// TODO: assign send/receive by state.IsInitiator - the initiator's send is the responder's receive
	// TODO: zero the chaining key, it must not outlive the handshake
	return TransportKeys{}
}
