package noise

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewHandshakeState(t *testing.T) {
	responderPublicKey := PublicKey{9}

	state := NewHandshakeState(responderPublicKey)

	require.Equal(t,
		"60e26daef327efc02ec335e2a025d2d016eb4206f87277f52d38d1988b78cd36",
		hex.EncodeToString(state.ChainingKey[:]),
	)
	require.Equal(t,
		"575bad75a5a30f85f58df113422a55d41873e357b40a3a2ea91f456c9508211a",
		hex.EncodeToString(state.Hash[:]),
	)
}
