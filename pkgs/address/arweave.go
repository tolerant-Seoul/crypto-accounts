package address

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
)

// ArweaveAddress generates Arweave (AR) addresses
// Arweave addresses are Base64URL-encoded SHA-256 hashes of RSA public keys
type ArweaveAddress struct{}

// NewArweaveAddress creates a new Arweave address generator
func NewArweaveAddress() *ArweaveAddress {
	return &ArweaveAddress{}
}

// ChainID returns the chain identifier
func (a *ArweaveAddress) ChainID() ChainID {
	return ChainArweave
}

// Generate creates an Arweave address from an RSA public key
// The public key should be the modulus (n) of the RSA key in raw bytes
// Typically 4096 bits = 512 bytes for Arweave
func (a *ArweaveAddress) Generate(publicKey []byte) (string, error) {
	// Arweave typically uses 4096-bit RSA keys (512 bytes modulus)
	// But we'll accept various sizes for flexibility
	if len(publicKey) < 256 {
		return "", fmt.Errorf("invalid public key length: expected at least 256 bytes (2048-bit RSA), got %d", len(publicKey))
	}

	// SHA-256 hash of the public key
	hash := sha256.Sum256(publicKey)

	// Base64URL encode (no padding)
	encoded := base64.RawURLEncoding.EncodeToString(hash[:])

	return encoded, nil
}

// GenerateFromModulus creates an Arweave address from RSA modulus
// This is the standard way Arweave addresses are generated
func (a *ArweaveAddress) GenerateFromModulus(modulus []byte) (string, error) {
	return a.Generate(modulus)
}

// Validate checks if an Arweave address is valid
func (a *ArweaveAddress) Validate(address string) bool {
	// Arweave addresses are 43 characters (Base64URL of SHA-256 = 32 bytes = 43 chars)
	if len(address) != 43 {
		return false
	}

	// Must be valid Base64URL
	decoded, err := base64.RawURLEncoding.DecodeString(address)
	if err != nil {
		return false
	}

	// Should decode to exactly 32 bytes (SHA-256 hash)
	if len(decoded) != 32 {
		return false
	}

	// Check for valid Base64URL characters
	for _, c := range address {
		if !isBase64URLChar(c) {
			return false
		}
	}

	return true
}

// isBase64URLChar checks if a character is valid in Base64URL encoding
func isBase64URLChar(c rune) bool {
	return (c >= 'A' && c <= 'Z') ||
		(c >= 'a' && c <= 'z') ||
		(c >= '0' && c <= '9') ||
		c == '-' || c == '_'
}

// GetAddressType returns the type of Arweave address
func (a *ArweaveAddress) GetAddressType(address string) (string, error) {
	if !a.Validate(address) {
		return "", ErrInvalidAddress
	}

	return "RSA-PSS Address", nil
}

// DecodeAddress decodes an Arweave address
func (a *ArweaveAddress) DecodeAddress(address string) (*AddressInfo, error) {
	if !a.Validate(address) {
		return nil, ErrInvalidAddress
	}

	decoded, err := base64.RawURLEncoding.DecodeString(address)
	if err != nil {
		return nil, err
	}

	return &AddressInfo{
		Address:   address,
		PublicKey: decoded, // This is the hash, not the actual public key
		ChainID:   ChainArweave,
		Type:      AddressTypeBase32, // Using Base32 as placeholder (actually Base64URL)
	}, nil
}

// FormatAddress formats an Arweave address for display
func (a *ArweaveAddress) FormatAddress(address string) string {
	if len(address) <= 12 {
		return address
	}
	return address[:6] + "..." + address[len(address)-6:]
}

// IsValidTransaction checks if a string looks like an Arweave transaction ID
// Transaction IDs use the same format as addresses (Base64URL of SHA-256)
func (a *ArweaveAddress) IsValidTransaction(txID string) bool {
	return a.Validate(txID)
}

// NormalizeAddress ensures the address uses standard Base64URL encoding
func (a *ArweaveAddress) NormalizeAddress(address string) (string, error) {
	// Replace any standard Base64 characters with URL-safe ones
	normalized := strings.ReplaceAll(address, "+", "-")
	normalized = strings.ReplaceAll(normalized, "/", "_")
	normalized = strings.TrimRight(normalized, "=")

	if !a.Validate(normalized) {
		return "", ErrInvalidAddress
	}

	return normalized, nil
}
