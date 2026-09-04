package noise

import (
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

const KeySize = curve25519.ScalarSize

// PrivateKey is a WireGuard static or ephemeral Curve25519 private key.
type PrivateKey [KeySize]byte

// PublicKey is a WireGuard static or ephemeral Curve25519 public key.
type PublicKey [KeySize]byte

// GeneratePrivateKey creates a new random private key.
func GeneratePrivateKey() (PrivateKey, error) {
	var key PrivateKey
	if _, err := rand.Read(key[:]); err != nil {
		return PrivateKey{}, fmt.Errorf("generate private key: %w", err)
	}

	// Clamped here as well as inside X25519, so the stored key is canonical.
	key[0] &= 248
	key[31] = (key[31] & 127) | 64
	return key, nil
}

// PublicKey derives the public key corresponding to this private key.
func (key PrivateKey) PublicKey() (PublicKey, error) {
	publicBytes, err := curve25519.X25519(key[:], curve25519.Basepoint)
	if err != nil {
		return PublicKey{}, fmt.Errorf("derive public key: %w", err)
	}

	var publicKey PublicKey
	copy(publicKey[:], publicBytes)
	return publicKey, nil
}

// SharedSecret performs X25519 Diffie-Hellman with the peer's public key.
func (key PrivateKey) SharedSecret(peerPublicKey PublicKey) ([KeySize]byte, error) {
	sharedBytes, err := curve25519.X25519(key[:], peerPublicKey[:])
	if err != nil {
		return [KeySize]byte{}, fmt.Errorf("derive shared secret: %w", err)
	}

	var sharedSecret [KeySize]byte
	copy(sharedSecret[:], sharedBytes)
	return sharedSecret, nil
}
