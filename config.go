package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"wireguard-mini/noise"
)

type config struct {
	Initiator     bool
	PrivateKey    noise.PrivateKey
	PeerPublicKey noise.PublicKey
}

func loadConfig(path string) (config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return config{}, fmt.Errorf("read config: %w", err)
	}

	var file struct {
		Initiator     bool   `json:"initiator"`
		PrivateKey    string `json:"privateKey"`
		PeerPublicKey string `json:"peerPublicKey"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		return config{}, fmt.Errorf("parse config: %w", err)
	}

	privateKey, err := decodeKey(file.PrivateKey)
	if err != nil {
		return config{}, fmt.Errorf("privateKey: %w", err)
	}
	peerPublicKey, err := decodeKey(file.PeerPublicKey)
	if err != nil {
		return config{}, fmt.Errorf("peerPublicKey: %w", err)
	}

	return config{
		Initiator:     file.Initiator,
		PrivateKey:    privateKey,
		PeerPublicKey: peerPublicKey,
	}, nil
}

func decodeKey(encoded string) ([noise.KeySize]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return [noise.KeySize]byte{}, err
	}
	if len(decoded) != noise.KeySize {
		return [noise.KeySize]byte{}, fmt.Errorf("got %d bytes, want %d", len(decoded), noise.KeySize)
	}

	var key [noise.KeySize]byte
	copy(key[:], decoded)
	return key, nil
}
