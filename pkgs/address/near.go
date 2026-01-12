package address

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

// NEARAddress generates NEAR Protocol addresses
type NEARAddress struct{}

// NewNEARAddress creates a new NEAR address generator
func NewNEARAddress() *NEARAddress {
	return &NEARAddress{}
}

// ChainID returns the chain identifier
func (n *NEARAddress) ChainID() ChainID {
	return ChainNEAR
}

// Generate creates a NEAR implicit address from an Ed25519 public key
// Public key should be 32 bytes
// Implicit addresses are 64 hex characters (the public key itself)
func (n *NEARAddress) Generate(publicKey []byte) (string, error) {
	if len(publicKey) != 32 {
		return "", fmt.Errorf("NEAR requires 32-byte Ed25519 public key, got %d bytes", len(publicKey))
	}

	// NEAR implicit addresses are hex-encoded public keys
	return hex.EncodeToString(publicKey), nil
}

// ValidateImplicit checks if an implicit address is valid
func (n *NEARAddress) ValidateImplicit(address string) bool {
	// Implicit addresses are 64 hex characters
	if len(address) != 64 {
		return false
	}

	// Must be valid hex
	_, err := hex.DecodeString(address)
	return err == nil
}

// ValidateNamed checks if a named address is valid
func (n *NEARAddress) ValidateNamed(address string) bool {
	// Named accounts:
	// - 2-64 characters
	// - Lowercase letters, digits, underscores, hyphens
	// - Must not start with hyphen or underscore
	// - Can contain periods for sub-accounts (alice.near)

	if len(address) < 2 || len(address) > 64 {
		return false
	}

	// Check for valid characters
	validPattern := regexp.MustCompile(`^[a-z0-9]([a-z0-9_-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9_-]*[a-z0-9])?)*$`)
	return validPattern.MatchString(address)
}

// Validate checks if a NEAR address is valid (either implicit or named)
func (n *NEARAddress) Validate(address string) bool {
	// Check if it's an implicit address first
	if n.ValidateImplicit(address) {
		return true
	}

	// Check if it's a named address
	return n.ValidateNamed(address)
}

// IsImplicit returns true if the address is an implicit address
func (n *NEARAddress) IsImplicit(address string) bool {
	return n.ValidateImplicit(address)
}

// IsNamed returns true if the address is a named address
func (n *NEARAddress) IsNamed(address string) bool {
	return !n.ValidateImplicit(address) && n.ValidateNamed(address)
}

// DecodeAddress decodes a NEAR address
func (n *NEARAddress) DecodeAddress(address string) (*AddressInfo, error) {
	if !n.Validate(address) {
		return nil, ErrInvalidAddress
	}

	info := &AddressInfo{
		Address: address,
		ChainID: ChainNEAR,
	}

	if n.IsImplicit(address) {
		decoded, _ := hex.DecodeString(address)
		info.PublicKey = decoded
		info.Type = AddressTypeBase58 // Actually hex
	} else {
		info.PublicKey = []byte(address) // Named address
		info.Type = AddressTypeBase58
	}

	return info, nil
}

// GetTopLevelAccount returns the top-level account for a sub-account
// e.g., "bob.alice.near" -> "near"
func (n *NEARAddress) GetTopLevelAccount(address string) string {
	parts := strings.Split(address, ".")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return address
}

// GetParentAccount returns the parent account for a sub-account
// e.g., "bob.alice.near" -> "alice.near"
func (n *NEARAddress) GetParentAccount(address string) string {
	parts := strings.Split(address, ".")
	if len(parts) > 1 {
		return strings.Join(parts[1:], ".")
	}
	return ""
}
