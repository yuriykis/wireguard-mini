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

// GeneratePrivateKey creates a new private key using the operating system's
// cryptographically secure random number generator.
func GeneratePrivateKey() (PrivateKey, error) {
	var key PrivateKey
	if _, err := rand.Read(key[:]); err != nil {
		return PrivateKey{}, fmt.Errorf("generate private key: %w", err)
	}

	// X25519 also clamps its scalar internally. Doing it here ensures the
	// stored key itself has WireGuard's canonical private-key representation.
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

// SharedSecret performs X25519 Diffie-Hellman using the local private key and
// the peer's public key. X25519 rejects low-order public keys whose result
// would be the all-zero shared secret.
func (key PrivateKey) SharedSecret(peerPublicKey PublicKey) ([KeySize]byte, error) {
	sharedBytes, err := curve25519.X25519(key[:], peerPublicKey[:])
	if err != nil {
		return [KeySize]byte{}, fmt.Errorf("derive shared secret: %w", err)
	}

	var sharedSecret [KeySize]byte
	copy(sharedSecret[:], sharedBytes)
	return sharedSecret, nil
}
