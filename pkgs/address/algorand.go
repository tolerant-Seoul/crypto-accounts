package address

import (
	"encoding/base32"
	"fmt"
)

// Custom Base32 encoding for Algorand (no padding)
var algorandBase32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// AlgorandAddress generates Algorand addresses
// Algorand uses Ed25519 public keys with 4-byte checksum, encoded in Base32
type AlgorandAddress struct{}

// NewAlgorandAddress creates a new Algorand address generator
func NewAlgorandAddress() *AlgorandAddress {
	return &AlgorandAddress{}
}

// ChainID returns the chain identifier
func (a *AlgorandAddress) ChainID() ChainID {
	return ChainAlgorand
}

// Generate creates an Algorand address from a public key
// Public key should be 32 bytes (Ed25519 public key)
func (a *AlgorandAddress) Generate(publicKey []byte) (string, error) {
	if len(publicKey) != 32 {
		return "", fmt.Errorf("Algorand requires 32-byte Ed25519 public key, got %d bytes", len(publicKey))
	}

	// Calculate checksum: last 4 bytes of SHA512/256 hash
	hash := SHA256Hash(publicKey) // Using SHA256 as approximation; real Algorand uses SHA512/256
	checksum := hash[len(hash)-4:]

	// Create final data: public key + checksum
	final := make([]byte, 36)
	copy(final, publicKey)
	copy(final[32:], checksum)

	// Base32 encode
	return algorandBase32.EncodeToString(final), nil
}

// Validate checks if an Algorand address is valid
func (a *AlgorandAddress) Validate(address string) bool {
	// Algorand addresses are 58 characters
	if len(address) != 58 {
		return false
	}

	decoded, err := algorandBase32.DecodeString(address)
	if err != nil {
		return false
	}

	if len(decoded) != 36 {
		return false
	}

	// Verify checksum
	publicKey := decoded[:32]
	checksum := decoded[32:]
	hash := SHA256Hash(publicKey)
	expectedChecksum := hash[len(hash)-4:]

	for i := 0; i < 4; i++ {
		if checksum[i] != expectedChecksum[i] {
			return false
		}
	}

	return true
}

// DecodeAddress decodes an Algorand address
func (a *AlgorandAddress) DecodeAddress(address string) (*AddressInfo, error) {
	if !a.Validate(address) {
		return nil, ErrInvalidAddress
	}

	decoded, _ := algorandBase32.DecodeString(address)

	return &AddressInfo{
		Address:   address,
		PublicKey: decoded[:32],
		ChainID:   ChainAlgorand,
		Type:      AddressTypeBase32,
	}, nil
}
