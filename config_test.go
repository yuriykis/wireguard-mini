package main

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"wireguard-mini/noise"
)

func writeConfig(t *testing.T, content string) string {
	path := filepath.Join(t.TempDir(), "config.json")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

func TestLoadConfigDecodesRoleAndKeys(t *testing.T) {
	privateKey := noise.PrivateKey{1, 2, 3}
	peerPublicKey := noise.PublicKey{4, 5, 6}
	path := writeConfig(t, `{
		"initiator": true,
		"privateKey": "`+base64.StdEncoding.EncodeToString(privateKey[:])+`",
		"peerPublicKey": "`+base64.StdEncoding.EncodeToString(peerPublicKey[:])+`"
	}`)

	loaded, err := loadConfig(path)
	require.NoError(t, err)
	require.True(t, loaded.Initiator)
	require.Equal(t, privateKey, loaded.PrivateKey)
	require.Equal(t, peerPublicKey, loaded.PeerPublicKey)
}

func TestLoadConfigRejectsKeyOfWrongLength(t *testing.T) {
	path := writeConfig(t, `{
		"privateKey": "`+base64.StdEncoding.EncodeToString([]byte("too short"))+`",
		"peerPublicKey": "`+base64.StdEncoding.EncodeToString(make([]byte, noise.KeySize))+`"
	}`)

	_, err := loadConfig(path)
	require.ErrorContains(t, err, "privateKey")
}
