package noise

const replayWindowSize = 64

// ReplayWindow remembers which transport counters a peer has already used.
type ReplayWindow struct {
	highest uint64
	seen    uint64
}

// CheckCounter reports whether the counter is fresh, and records it when it is.
func (window *ReplayWindow) CheckCounter(counter uint64) bool {
	if counter > window.highest {
		// Go defines a shift wider than the operand as zero, so a jump past the
		// whole window clears it without a special case.
		window.seen <<= counter - window.highest
		window.highest = counter
		window.seen |= 1
		return true
	}

	if window.highest-counter >= replayWindowSize {
		return false
	}

	bit := uint64(1) << (window.highest - counter)
	if window.seen&bit != 0 {
		return false
	}

	window.seen |= bit
	return true
}
