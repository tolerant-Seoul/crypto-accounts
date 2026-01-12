package address

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// EthereumAddress generates Ethereum-style addresses
// Also used by: BSC, Polygon, Fantom, Optimism, Arbitrum, VeChain, Theta, etc.
type EthereumAddress struct {
	chainID ChainID
}

// NewEthereumAddress creates a new Ethereum address generator
func NewEthereumAddress() *EthereumAddress {
	return &EthereumAddress{chainID: ChainEthereum}
}

// NewEVMAddress creates an address generator for any EVM-compatible chain
func NewEVMAddress(chainID ChainID) *EthereumAddress {
	return &EthereumAddress{chainID: chainID}
}

// ChainID returns the chain identifier
func (e *EthereumAddress) ChainID() ChainID {
	return e.chainID
}

// Generate creates an Ethereum address from a public key
// Public key should be 64 bytes (uncompressed without 0x04 prefix)
// or 65 bytes (uncompressed with 0x04 prefix)
func (e *EthereumAddress) Generate(publicKey []byte) (string, error) {
	var key []byte

	switch len(publicKey) {
	case 64:
		// Already uncompressed without prefix
		key = publicKey
	case 65:
		// Uncompressed with 0x04 prefix
		if publicKey[0] != 0x04 {
			return "", fmt.Errorf("invalid uncompressed public key prefix")
		}
		key = publicKey[1:]
	case 33:
		// Compressed public key - need to decompress
		return "", fmt.Errorf("compressed public keys not supported, please decompress first")
	default:
		return "", ErrInvalidPublicKey
	}

	// Keccak-256 hash of the public key
	hash := Keccak256(key)

	// Take the last 20 bytes
	address := hash[12:]

	// Apply EIP-55 checksum
	return e.toChecksumAddress(address), nil
}

// toChecksumAddress converts address bytes to EIP-55 checksum format
func (e *EthereumAddress) toChecksumAddress(address []byte) string {
	// Convert to hex without 0x prefix
	hexAddr := hex.EncodeToString(address)

	// Get Keccak hash of lowercase hex address
	hash := Keccak256([]byte(hexAddr))

	// Build checksummed address
	var result strings.Builder
	result.WriteString("0x")

	for i, c := range hexAddr {
		// If character is a letter (a-f) and corresponding nibble is >= 8, uppercase it
		if c >= 'a' && c <= 'f' {
			// Get the nibble from hash
			nibble := hash[i/2]
			if i%2 == 0 {
				nibble = nibble >> 4
			} else {
				nibble = nibble & 0x0F
			}

			if nibble >= 8 {
				result.WriteByte(byte(c) - 32) // Convert to uppercase
			} else {
				result.WriteByte(byte(c))
			}
		} else {
			result.WriteByte(byte(c))
		}
	}

	return result.String()
}

// Validate checks if an address is valid
func (e *EthereumAddress) Validate(address string) bool {
	// Must start with 0x
	if !strings.HasPrefix(address, "0x") && !strings.HasPrefix(address, "0X") {
		return false
	}

	// Must be 42 characters (0x + 40 hex chars)
	if len(address) != 42 {
		return false
	}

	// Must be valid hex
	_, err := hex.DecodeString(address[2:])
	if err != nil {
		return false
	}

	return true
}

// ValidateChecksum validates an address including EIP-55 checksum
func (e *EthereumAddress) ValidateChecksum(address string) bool {
	if !e.Validate(address) {
		return false
	}

	// Decode address
	addrBytes, _ := hex.DecodeString(strings.ToLower(address[2:]))

	// Generate checksummed version
	checksummed := e.toChecksumAddress(addrBytes)

	// Compare
	return address == checksummed
}

// FromPrivateKey generates an address from a private key
// This requires secp256k1 public key derivation
func (e *EthereumAddress) FromPrivateKey(privateKey []byte) (string, error) {
	if len(privateKey) != 32 {
		return "", ErrInvalidPrivateKey
	}

	// Note: This would require secp256k1 library to derive public key
	// The caller should derive the public key and use Generate() instead
	return "", fmt.Errorf("use Generate() with derived public key instead")
}

// DecodeAddress decodes an Ethereum address
func (e *EthereumAddress) DecodeAddress(address string) (*AddressInfo, error) {
	if !e.Validate(address) {
		return nil, ErrInvalidAddress
	}

	addrBytes, err := hex.DecodeString(address[2:])
	if err != nil {
		return nil, err
	}

	return &AddressInfo{
		Address:   address,
		PublicKey: addrBytes,
		ChainID:   e.chainID,
		Type:      AddressTypeEthereum,
	}, nil
}

// EVMChains returns a map of all EVM-compatible chain generators
func EVMChains() map[ChainID]*EthereumAddress {
	return map[ChainID]*EthereumAddress{
		ChainEthereum:        NewEVMAddress(ChainEthereum),
		ChainBSC:             NewEVMAddress(ChainBSC),
		ChainPolygon:         NewEVMAddress(ChainPolygon),
		ChainFantom:          NewEVMAddress(ChainFantom),
		ChainOptimism:        NewEVMAddress(ChainOptimism),
		ChainArbitrum:        NewEVMAddress(ChainArbitrum),
		ChainVeChain:         NewEVMAddress(ChainVeChain),
		ChainTheta:           NewEVMAddress(ChainTheta),
		ChainEthereumClassic: NewEVMAddress(ChainEthereumClassic),
	}
}
