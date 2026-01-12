package address

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// Flow address constants
const (
	FlowAddressLength = 8 // Flow addresses are 8 bytes (16 hex chars)
)

// Flow network magic bytes for address validation
var (
	FlowMainnetMagic = []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01} // Mainnet
	FlowTestnetMagic = []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00} // Testnet
)

// FlowAddress generates Flow (FLOW) addresses
// Flow uses a unique address system where addresses are assigned by the network
// They are not directly derived from public keys
type FlowAddress struct {
	testnet bool
}

// NewFlowAddress creates a new Flow address generator for mainnet
func NewFlowAddress() *FlowAddress {
	return &FlowAddress{testnet: false}
}

// NewFlowTestnetAddress creates a new Flow address generator for testnet
func NewFlowTestnetAddress() *FlowAddress {
	return &FlowAddress{testnet: true}
}

// ChainID returns the chain identifier
func (f *FlowAddress) ChainID() ChainID {
	return ChainFlow
}

// Generate creates a Flow-compatible hex representation of public key hash
// Note: Flow addresses are NOT derived from public keys directly
// They are assigned by the network. This generates a hash that can be used as a reference.
func (f *FlowAddress) Generate(publicKey []byte) (string, error) {
	if len(publicKey) != 32 && len(publicKey) != 33 && len(publicKey) != 64 && len(publicKey) != 65 {
		return "", fmt.Errorf("invalid public key length: got %d", len(publicKey))
	}

	// Hash the public key to create a pseudo-address
	// Note: This is for reference only - actual Flow addresses are network-assigned
	hash := Hash160(publicKey)

	// Take last 8 bytes to create an address-like format
	addressBytes := hash[len(hash)-8:]

	return "0x" + hex.EncodeToString(addressBytes), nil
}

// GenerateFromIndex creates a Flow address from an index (for illustration)
// In practice, Flow addresses are assigned by the network
func (f *FlowAddress) GenerateFromIndex(index uint64) string {
	addressBytes := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		addressBytes[i] = byte(index & 0xFF)
		index >>= 8
	}
	return "0x" + hex.EncodeToString(addressBytes)
}

// Validate checks if a Flow address is valid
func (f *FlowAddress) Validate(address string) bool {
	// Remove 0x prefix if present
	cleaned := strings.TrimPrefix(address, "0x")
	cleaned = strings.TrimPrefix(cleaned, "0X")

	// Must be exactly 16 hex characters (8 bytes)
	if len(cleaned) != 16 {
		return false
	}

	// Must be valid hex
	_, err := hex.DecodeString(cleaned)
	if err != nil {
		return false
	}

	// Flow addresses cannot be all zeros (reserved)
	allZeros := true
	for _, c := range cleaned {
		if c != '0' {
			allZeros = false
			break
		}
	}
	if allZeros {
		return false
	}

	return true
}

// GetAddressType returns the type of Flow address
func (f *FlowAddress) GetAddressType(address string) (string, error) {
	if !f.Validate(address) {
		return "", ErrInvalidAddress
	}

	cleaned := strings.TrimPrefix(address, "0x")
	decoded, _ := hex.DecodeString(cleaned)

	// Check for service account (usually very low numbers)
	var value uint64
	for _, b := range decoded {
		value = (value << 8) | uint64(b)
	}

	if value < 100 {
		return "Service Account", nil
	}

	return "User Account", nil
}

// DecodeAddress decodes a Flow address
func (f *FlowAddress) DecodeAddress(address string) (*AddressInfo, error) {
	if !f.Validate(address) {
		return nil, ErrInvalidAddress
	}

	cleaned := strings.TrimPrefix(address, "0x")
	decoded, err := hex.DecodeString(cleaned)
	if err != nil {
		return nil, err
	}

	return &AddressInfo{
		Address:   address,
		PublicKey: decoded,
		ChainID:   ChainFlow,
		Type:      AddressTypeEthereum, // Using Ethereum type as both use hex format
	}, nil
}

// ParseAddress parses a Flow address and returns its numeric value
func (f *FlowAddress) ParseAddress(address string) (uint64, error) {
	if !f.Validate(address) {
		return 0, ErrInvalidAddress
	}

	cleaned := strings.TrimPrefix(address, "0x")
	decoded, err := hex.DecodeString(cleaned)
	if err != nil {
		return 0, err
	}

	var value uint64
	for _, b := range decoded {
		value = (value << 8) | uint64(b)
	}

	return value, nil
}
