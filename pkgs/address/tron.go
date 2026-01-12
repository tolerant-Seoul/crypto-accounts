package address

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// TRON address constants
const (
	TronAddressPrefix byte = 0x41 // Mainnet prefix, results in addresses starting with 'T'
	TronTestnetPrefix byte = 0xa0 // Testnet/Shasta prefix
)

// TronAddress generates TRON addresses
type TronAddress struct {
	testnet bool
}

// NewTronAddress creates a new TRON address generator
func NewTronAddress(testnet bool) *TronAddress {
	return &TronAddress{testnet: testnet}
}

// ChainID returns the chain identifier
func (t *TronAddress) ChainID() ChainID {
	return ChainTron
}

// Generate creates a TRON address from a public key
// Public key should be 64 bytes (uncompressed without 0x04 prefix)
// or 65 bytes (uncompressed with 0x04 prefix)
func (t *TronAddress) Generate(publicKey []byte) (string, error) {
	var key []byte

	switch len(publicKey) {
	case 64:
		key = publicKey
	case 65:
		if publicKey[0] != 0x04 {
			return "", fmt.Errorf("invalid uncompressed public key prefix")
		}
		key = publicKey[1:]
	default:
		return "", ErrInvalidPublicKey
	}

	// 1. Keccak-256 hash of the public key
	hash := Keccak256(key)

	// 2. Take the last 20 bytes
	addressBytes := hash[12:]

	// 3. Add prefix byte (0x41 for mainnet)
	prefix := TronAddressPrefix
	if t.testnet {
		prefix = TronTestnetPrefix
	}

	initialAddress := make([]byte, 21)
	initialAddress[0] = prefix
	copy(initialAddress[1:], addressBytes)

	// 4. Calculate checksum (first 4 bytes of double SHA256)
	checksum := DoubleSHA256(initialAddress)[:4]

	// 5. Append checksum and Base58 encode
	fullAddress := append(initialAddress, checksum...)

	return Base58Encode(fullAddress), nil
}

// GenerateHex creates a TRON address in hex format (41 prefix + 20 bytes)
func (t *TronAddress) GenerateHex(publicKey []byte) (string, error) {
	var key []byte

	switch len(publicKey) {
	case 64:
		key = publicKey
	case 65:
		if publicKey[0] != 0x04 {
			return "", fmt.Errorf("invalid uncompressed public key prefix")
		}
		key = publicKey[1:]
	default:
		return "", ErrInvalidPublicKey
	}

	hash := Keccak256(key)
	addressBytes := hash[12:]

	prefix := TronAddressPrefix
	if t.testnet {
		prefix = TronTestnetPrefix
	}

	result := make([]byte, 21)
	result[0] = prefix
	copy(result[1:], addressBytes)

	return hex.EncodeToString(result), nil
}

// Validate checks if a TRON address is valid
func (t *TronAddress) Validate(address string) bool {
	// Check if it's a hex address
	if strings.HasPrefix(address, "41") || strings.HasPrefix(address, "a0") {
		if len(address) == 42 {
			_, err := hex.DecodeString(address)
			return err == nil
		}
		return false
	}

	// Validate Base58 address
	if !strings.HasPrefix(address, "T") {
		return false
	}

	decoded, err := Base58Decode(address)
	if err != nil {
		return false
	}

	if len(decoded) != 25 {
		return false
	}

	// Verify prefix
	prefix := decoded[0]
	expectedPrefix := TronAddressPrefix
	if t.testnet {
		expectedPrefix = TronTestnetPrefix
	}
	if prefix != expectedPrefix {
		return false
	}

	// Verify checksum
	payload := decoded[:21]
	checksum := decoded[21:]
	expectedChecksum := DoubleSHA256(payload)[:4]

	for i := 0; i < 4; i++ {
		if checksum[i] != expectedChecksum[i] {
			return false
		}
	}

	return true
}

// DecodeAddress decodes a TRON address
func (t *TronAddress) DecodeAddress(address string) (*AddressInfo, error) {
	// Handle hex address
	if strings.HasPrefix(address, "41") || strings.HasPrefix(address, "a0") {
		decoded, err := hex.DecodeString(address)
		if err != nil {
			return nil, err
		}
		return &AddressInfo{
			Address:   address,
			PublicKey: decoded[1:], // Remove prefix
			ChainID:   ChainTron,
			Type:      AddressTypeBase58Check,
			Version:   decoded[0],
		}, nil
	}

	// Decode Base58 address
	decoded, err := Base58Decode(address)
	if err != nil {
		return nil, err
	}

	if len(decoded) != 25 {
		return nil, ErrInvalidAddress
	}

	return &AddressInfo{
		Address:   address,
		PublicKey: decoded[1:21], // Without prefix and checksum
		ChainID:   ChainTron,
		Type:      AddressTypeBase58Check,
		Version:   decoded[0],
	}, nil
}

// HexToBase58 converts a hex TRON address to Base58 format
func (t *TronAddress) HexToBase58(hexAddr string) (string, error) {
	decoded, err := hex.DecodeString(hexAddr)
	if err != nil {
		return "", err
	}

	if len(decoded) != 21 {
		return "", fmt.Errorf("invalid hex address length")
	}

	checksum := DoubleSHA256(decoded)[:4]
	fullAddress := append(decoded, checksum...)

	return Base58Encode(fullAddress), nil
}

// Base58ToHex converts a Base58 TRON address to hex format
func (t *TronAddress) Base58ToHex(base58Addr string) (string, error) {
	decoded, err := Base58Decode(base58Addr)
	if err != nil {
		return "", err
	}

	if len(decoded) != 25 {
		return "", fmt.Errorf("invalid Base58 address length")
	}

	// Return first 21 bytes (without checksum)
	return hex.EncodeToString(decoded[:21]), nil
}
