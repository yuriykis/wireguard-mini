package noise

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCheckCounterAcceptsACounterAboveTheHighestOne(t *testing.T) {
	var window ReplayWindow

	require.True(t, window.CheckCounter(1))
	require.True(t, window.CheckCounter(2))
	require.True(t, window.CheckCounter(100))
}

func TestCheckCounterRecordsTheAcceptedCounter(t *testing.T) {
	window := ReplayWindow{highest: 20, seen: 0b1}

	require.True(t, window.CheckCounter(23))
	require.Equal(t, uint64(23), window.highest)
	require.Equal(t, uint64(0b1001), window.seen)
}

func TestCheckCounterClearsTheWindowOnAFarJump(t *testing.T) {
	window := ReplayWindow{highest: 20, seen: ^uint64(0)}

	require.True(t, window.CheckCounter(346))
	require.Equal(t, uint64(346), window.highest)
	require.Equal(t, uint64(0b1), window.seen)
}

func TestCheckCounterRejectsACounterSeenBefore(t *testing.T) {
	window := ReplayWindow{highest: 100, seen: 0b1}

	require.False(t, window.CheckCounter(100))
	require.Equal(t, uint64(0b1), window.seen)
}

func TestCheckCounterAcceptsALateCounterInsideTheWindow(t *testing.T) {
	window := ReplayWindow{highest: 20, seen: 0b1}

	require.True(t, window.CheckCounter(19))
	require.Equal(t, uint64(20), window.highest)
	require.Equal(t, uint64(0b11), window.seen)
	require.False(t, window.CheckCounter(19))
}

func TestCheckCounterAcceptsTheFirstCounterOfASession(t *testing.T) {
	var window ReplayWindow

	require.True(t, window.CheckCounter(0))
	require.False(t, window.CheckCounter(0))
}

func TestCheckCounterRejectsACounterOlderThanTheWindow(t *testing.T) {
	window := ReplayWindow{highest: 100}

	require.False(t, window.CheckCounter(36))
	require.False(t, window.CheckCounter(36))
	require.True(t, window.CheckCounter(37))
	require.Equal(t, uint64(100), window.highest)
}
