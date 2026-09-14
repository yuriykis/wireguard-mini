package noise

const replayWindowSize = 64

// ReplayWindow remembers which transport counters a peer has already used.
type ReplayWindow struct {
	highest uint64
	seen    uint64
}

// CheckCounter reports whether the counter is fresh, and records it when it is.
func (window *ReplayWindow) CheckCounter(counter uint64) bool {
	// Reject a counter that is older than everything the window still covers.

	// Move the window forward when the counter is above the highest one seen,
	// dropping the bits that fall off the back.

	// Reject a counter whose bit is already set.

	// Set the bit for this counter and accept.

	return false // TODO: implement
}
