package address

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// Aptos signature scheme identifiers
const (
	AptosEd25519Scheme   byte = 0x00
	AptosSecp256k1Scheme byte = 0x01
	AptosMultiEd25519    byte = 0x02
)

// AptosAddress generates Aptos addresses
type AptosAddress struct{}

// NewAptosAddress creates a new Aptos address generator
func NewAptosAddress() *AptosAddress {
	return &AptosAddress{}
}

// ChainID returns the chain identifier
func (a *AptosAddress) ChainID() ChainID {
	return ChainAptos
}

// Generate creates an Aptos address from an Ed25519 public key
// Public key should be 32 bytes
func (a *AptosAddress) Generate(publicKey []byte) (string, error) {
	return a.GenerateWithScheme(publicKey, AptosEd25519Scheme)
}

// GenerateWithScheme creates an Aptos address with a specific signature scheme
func (a *AptosAddress) GenerateWithScheme(publicKey []byte, scheme byte) (string, error) {
	var expectedLen int
	switch scheme {
	case AptosEd25519Scheme:
		expectedLen = 32
	case AptosSecp256k1Scheme:
		expectedLen = 33
	default:
		return "", fmt.Errorf("unsupported signature scheme: %d", scheme)
	}

	if len(publicKey) != expectedLen {
		return "", fmt.Errorf("invalid public key length: expected %d, got %d", expectedLen, len(publicKey))
	}

	// Aptos address generation:
	// 1. Append scheme byte to public key
	// 2. SHA3-256 hash
	// 3. Result is the 32-byte address
	data := make([]byte, len(publicKey)+1)
	copy(data, publicKey)
	data[len(publicKey)] = scheme

	hash := SHA3256(data)

	// Format as 0x-prefixed hex string
	return "0x" + hex.EncodeToString(hash), nil
}

// Validate checks if an Aptos address is valid
func (a *AptosAddress) Validate(address string) bool {
	// Must start with 0x
	if !strings.HasPrefix(address, "0x") {
		return false
	}

	// Remove 0x prefix
	hexPart := address[2:]

	// Must be 64 hex characters (32 bytes)
	if len(hexPart) != 64 {
		// Aptos also allows shorter addresses (without leading zeros)
		if len(hexPart) > 64 {
			return false
		}
	}

	// Must be valid hex
	_, err := hex.DecodeString(hexPart)
	return err == nil
}

// DecodeAddress decodes an Aptos address
func (a *AptosAddress) DecodeAddress(address string) (*AddressInfo, error) {
	if !a.Validate(address) {
		return nil, ErrInvalidAddress
	}

	hexPart := address[2:]
	// Pad with leading zeros if needed
	if len(hexPart) < 64 {
		hexPart = strings.Repeat("0", 64-len(hexPart)) + hexPart
	}

	decoded, _ := hex.DecodeString(hexPart)

	return &AddressInfo{
		Address:   address,
		PublicKey: decoded,
		ChainID:   ChainAptos,
		Type:      AddressTypeBase58, // Actually hex, but no specific type
	}, nil
}
