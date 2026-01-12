package address

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// Sui signature scheme flags
const (
	SuiEd25519Flag     byte = 0x00
	SuiSecp256k1Flag   byte = 0x01
	SuiSecp256r1Flag   byte = 0x02
	SuiMultiSigFlag    byte = 0x03
)

// SuiAddress generates Sui addresses
type SuiAddress struct{}

// NewSuiAddress creates a new Sui address generator
func NewSuiAddress() *SuiAddress {
	return &SuiAddress{}
}

// ChainID returns the chain identifier
func (s *SuiAddress) ChainID() ChainID {
	return ChainSui
}

// Generate creates a Sui address from an Ed25519 public key
// Public key should be 32 bytes
func (s *SuiAddress) Generate(publicKey []byte) (string, error) {
	return s.GenerateWithScheme(publicKey, SuiEd25519Flag)
}

// GenerateWithScheme creates a Sui address with a specific signature scheme
func (s *SuiAddress) GenerateWithScheme(publicKey []byte, flag byte) (string, error) {
	var expectedLen int
	switch flag {
	case SuiEd25519Flag:
		expectedLen = 32
	case SuiSecp256k1Flag, SuiSecp256r1Flag:
		expectedLen = 33
	default:
		return "", fmt.Errorf("unsupported signature scheme: %d", flag)
	}

	if len(publicKey) != expectedLen {
		return "", fmt.Errorf("invalid public key length: expected %d, got %d", expectedLen, len(publicKey))
	}

	// Sui address generation:
	// 1. Prepend flag byte to public key
	// 2. BLAKE2b-256 hash
	// 3. Result is the 32-byte address
	data := make([]byte, 1+len(publicKey))
	data[0] = flag
	copy(data[1:], publicKey)

	hash := Blake2b256(data)

	// Format as 0x-prefixed hex string
	return "0x" + hex.EncodeToString(hash), nil
}

// Validate checks if a Sui address is valid
func (s *SuiAddress) Validate(address string) bool {
	// Must start with 0x
	if !strings.HasPrefix(address, "0x") {
		return false
	}

	// Remove 0x prefix
	hexPart := address[2:]

	// Must be 64 hex characters (32 bytes)
	if len(hexPart) != 64 {
		return false
	}

	// Must be valid hex
	_, err := hex.DecodeString(hexPart)
	return err == nil
}

// DecodeAddress decodes a Sui address
func (s *SuiAddress) DecodeAddress(address string) (*AddressInfo, error) {
	if !s.Validate(address) {
		return nil, ErrInvalidAddress
	}

	decoded, _ := hex.DecodeString(address[2:])

	return &AddressInfo{
		Address:   address,
		PublicKey: decoded,
		ChainID:   ChainSui,
		Type:      AddressTypeBase58, // Actually hex
	}, nil
}
