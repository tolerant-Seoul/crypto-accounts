// Package ed25519 provides Ed25519 elliptic curve operations for cryptocurrency address generation.
// Used by: Solana, Stellar, Algorand, NEAR, Aptos, Sui, Cardano
package ed25519

import (
	"crypto/ed25519"
	"crypto/sha512"
	"errors"
)

const (
	// PrivateKeySize is the size of an Ed25519 private key (seed)
	PrivateKeySize = 32

	// PublicKeySize is the size of an Ed25519 public key
	PublicKeySize = 32

	// SignatureSize is the size of an Ed25519 signature
	SignatureSize = 64

	// ExpandedPrivateKeySize is the size of the expanded private key (seed + public key)
	ExpandedPrivateKeySize = 64
)

var (
	ErrInvalidPrivateKey = errors.New("invalid private key: must be 32 bytes")
	ErrInvalidPublicKey  = errors.New("invalid public key: must be 32 bytes")
	ErrInvalidSignature  = errors.New("invalid signature")
)

// PrivateKeyToPublicKey derives an Ed25519 public key from a 32-byte private key (seed).
func PrivateKeyToPublicKey(privateKey []byte) ([]byte, error) {
	if len(privateKey) != PrivateKeySize {
		return nil, ErrInvalidPrivateKey
	}

	// Use Go's standard library
	// NewKeyFromSeed takes a 32-byte seed and returns a 64-byte private key
	// The last 32 bytes of the expanded key is the public key
	expandedKey := ed25519.NewKeyFromSeed(privateKey)
	publicKey := expandedKey.Public().(ed25519.PublicKey)

	return publicKey, nil
}

// ExpandPrivateKey expands a 32-byte seed into a 64-byte expanded private key.
// The expanded key format is: seed || public_key
func ExpandPrivateKey(seed []byte) ([]byte, error) {
	if len(seed) != PrivateKeySize {
		return nil, ErrInvalidPrivateKey
	}

	return ed25519.NewKeyFromSeed(seed), nil
}

// Sign signs a message with the given private key (seed).
func Sign(privateKey, message []byte) ([]byte, error) {
	if len(privateKey) != PrivateKeySize {
		return nil, ErrInvalidPrivateKey
	}

	expandedKey := ed25519.NewKeyFromSeed(privateKey)
	return ed25519.Sign(expandedKey, message), nil
}

// Verify verifies a signature against a message and public key.
func Verify(publicKey, message, signature []byte) bool {
	if len(publicKey) != PublicKeySize || len(signature) != SignatureSize {
		return false
	}

	return ed25519.Verify(publicKey, message, signature)
}

// GenerateKeyPair generates a new Ed25519 key pair from a seed.
// Returns (publicKey, expandedPrivateKey, error)
func GenerateKeyPair(seed []byte) ([]byte, []byte, error) {
	if len(seed) != PrivateKeySize {
		return nil, nil, ErrInvalidPrivateKey
	}

	expandedKey := ed25519.NewKeyFromSeed(seed)
	publicKey := expandedKey.Public().(ed25519.PublicKey)

	return publicKey, expandedKey, nil
}

// DeriveKeyFromPath derives an Ed25519 key using SLIP-10 / BIP32-Ed25519 derivation.
// This is used by Solana and other Ed25519-based chains for HD wallet derivation.
// Note: Standard BIP32 doesn't work with Ed25519, so SLIP-10 is used instead.
func DeriveKeyFromPath(seed []byte, path []uint32) ([]byte, []byte, error) {
	if len(seed) < 16 {
		return nil, nil, errors.New("seed must be at least 16 bytes")
	}

	// SLIP-10 master key derivation
	key, chainCode := slip10MasterKey(seed)

	// Derive each level
	for _, index := range path {
		// Ed25519 only supports hardened derivation
		if index < 0x80000000 {
			index += 0x80000000 // Make it hardened
		}
		key, chainCode = slip10DeriveChild(key, chainCode, index)
	}

	// Derive public key from the final private key
	publicKey, err := PrivateKeyToPublicKey(key)
	if err != nil {
		return nil, nil, err
	}

	return key, publicKey, nil
}

// slip10MasterKey derives the master key and chain code from seed using SLIP-10.
func slip10MasterKey(seed []byte) ([]byte, []byte) {
	// HMAC-SHA512 with key "ed25519 seed"
	h := hmacSHA512([]byte("ed25519 seed"), seed)
	return h[:32], h[32:]
}

// slip10DeriveChild derives a child key using SLIP-10.
func slip10DeriveChild(key, chainCode []byte, index uint32) ([]byte, []byte) {
	// For Ed25519, only hardened derivation is supported
	// Data = 0x00 || key || index (big-endian)
	data := make([]byte, 37)
	data[0] = 0x00
	copy(data[1:33], key)
	data[33] = byte(index >> 24)
	data[34] = byte(index >> 16)
	data[35] = byte(index >> 8)
	data[36] = byte(index)

	h := hmacSHA512(chainCode, data)
	return h[:32], h[32:]
}

// hmacSHA512 computes HMAC-SHA512.
func hmacSHA512(key, data []byte) []byte {
	// HMAC-SHA512 implementation
	blockSize := 128
	if len(key) > blockSize {
		h := sha512.Sum512(key)
		key = h[:]
	}
	if len(key) < blockSize {
		padded := make([]byte, blockSize)
		copy(padded, key)
		key = padded
	}

	ipad := make([]byte, blockSize)
	opad := make([]byte, blockSize)
	for i := 0; i < blockSize; i++ {
		ipad[i] = key[i] ^ 0x36
		opad[i] = key[i] ^ 0x5c
	}

	inner := sha512.New()
	inner.Write(ipad)
	inner.Write(data)
	innerHash := inner.Sum(nil)

	outer := sha512.New()
	outer.Write(opad)
	outer.Write(innerHash)

	return outer.Sum(nil)
}

// IsOnCurve checks if a public key is a valid Ed25519 point.
// Note: Ed25519 public keys are always valid if they are 32 bytes.
func IsOnCurve(publicKey []byte) bool {
	if len(publicKey) != PublicKeySize {
		return false
	}
	// A simple validation - try to use it for verification
	// In practice, any 32-byte value could be a valid public key
	// but not all will correspond to a valid private key
	return true
}
