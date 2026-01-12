package address

import (
	"fmt"
)

// SS58 network prefixes
const (
	SS58Polkadot  byte = 0  // Polkadot mainnet
	SS58Kusama    byte = 2  // Kusama
	SS58Generic   byte = 42 // Generic substrate
	SS58Westend   byte = 42 // Westend testnet
)

// PolkadotAddress generates Polkadot/Substrate SS58 addresses
type PolkadotAddress struct {
	networkPrefix byte
	chainID       ChainID
}

// NewPolkadotAddress creates a new Polkadot address generator
func NewPolkadotAddress() *PolkadotAddress {
	return &PolkadotAddress{networkPrefix: SS58Polkadot, chainID: ChainPolkadot}
}

// NewKusamaAddress creates a new Kusama address generator
func NewKusamaAddress() *PolkadotAddress {
	return &PolkadotAddress{networkPrefix: SS58Kusama, chainID: ChainPolkadot}
}

// NewSS58Address creates a new SS58 address generator with custom prefix
func NewSS58Address(prefix byte, chainID ChainID) *PolkadotAddress {
	return &PolkadotAddress{networkPrefix: prefix, chainID: chainID}
}

// ChainID returns the chain identifier
func (p *PolkadotAddress) ChainID() ChainID {
	return p.chainID
}

// Generate creates an SS58 address from a public key
// Public key should be 32 bytes (Sr25519 or Ed25519)
func (p *PolkadotAddress) Generate(publicKey []byte) (string, error) {
	if len(publicKey) != 32 {
		return "", fmt.Errorf("Polkadot requires 32-byte public key, got %d bytes", len(publicKey))
	}

	// SS58 format:
	// prefix (1 or 2 bytes) + account (32 bytes) + checksum (2 bytes)

	// Calculate checksum using BLAKE2b-512
	// Prepend with "SS58PRE" string
	ss58Prefix := []byte("SS58PRE")

	var payload []byte
	if p.networkPrefix < 64 {
		// Simple prefix (1 byte)
		payload = make([]byte, len(ss58Prefix)+1+32)
		copy(payload, ss58Prefix)
		payload[len(ss58Prefix)] = p.networkPrefix
		copy(payload[len(ss58Prefix)+1:], publicKey)
	} else {
		// Two-byte prefix for larger network IDs (64-16383)
		// For single-byte prefix values, just use simple encoding
		payload = make([]byte, len(ss58Prefix)+2+32)
		copy(payload, ss58Prefix)
		// Encode network prefix as two bytes
		prefixVal := uint16(p.networkPrefix)
		payload[len(ss58Prefix)] = byte(((prefixVal & 0xFC) >> 2) | 0x40)
		payload[len(ss58Prefix)+1] = byte((prefixVal >> 8) | ((prefixVal & 0x03) << 6))
		copy(payload[len(ss58Prefix)+2:], publicKey)
	}

	// Calculate checksum
	hash := Blake2b512(payload)
	checksum := hash[:2]

	// Build final address
	var final []byte
	if p.networkPrefix < 64 {
		final = make([]byte, 1+32+2)
		final[0] = p.networkPrefix
		copy(final[1:], publicKey)
		copy(final[33:], checksum)
	} else {
		final = make([]byte, 2+32+2)
		prefixVal := uint16(p.networkPrefix)
		final[0] = byte(((prefixVal & 0xFC) >> 2) | 0x40)
		final[1] = byte((prefixVal >> 8) | ((prefixVal & 0x03) << 6))
		copy(final[2:], publicKey)
		copy(final[34:], checksum)
	}

	// Base58 encode
	return Base58Encode(final), nil
}

// Validate checks if an SS58 address is valid
func (p *PolkadotAddress) Validate(address string) bool {
	decoded, err := Base58Decode(address)
	if err != nil {
		return false
	}

	// Minimum length check
	if len(decoded) < 35 {
		return false
	}

	// Determine prefix length and extract network prefix
	var prefixLen int
	var networkPrefix byte
	if decoded[0] < 64 {
		prefixLen = 1
		networkPrefix = decoded[0]
	} else if decoded[0] < 128 {
		prefixLen = 2
		networkPrefix = byte(((decoded[0] & 0x3F) << 2) | (decoded[1] >> 6))
	} else {
		return false
	}

	// Check if network prefix matches
	if p.networkPrefix != 255 && networkPrefix != p.networkPrefix {
		return false
	}

	// Verify length: prefix + 32 bytes + 2 bytes checksum
	if len(decoded) != prefixLen+32+2 {
		return false
	}

	// Verify checksum
	publicKey := decoded[prefixLen : prefixLen+32]
	providedChecksum := decoded[prefixLen+32:]

	ss58Prefix := []byte("SS58PRE")
	payload := make([]byte, len(ss58Prefix)+prefixLen+32)
	copy(payload, ss58Prefix)
	copy(payload[len(ss58Prefix):], decoded[:prefixLen])
	copy(payload[len(ss58Prefix)+prefixLen:], publicKey)

	hash := Blake2b512(payload)
	expectedChecksum := hash[:2]

	return providedChecksum[0] == expectedChecksum[0] && providedChecksum[1] == expectedChecksum[1]
}

// DecodeAddress decodes an SS58 address
func (p *PolkadotAddress) DecodeAddress(address string) (*AddressInfo, error) {
	decoded, err := Base58Decode(address)
	if err != nil {
		return nil, err
	}

	// Determine prefix length
	var prefixLen int
	var networkPrefix byte
	if decoded[0] < 64 {
		prefixLen = 1
		networkPrefix = decoded[0]
	} else if decoded[0] < 128 {
		prefixLen = 2
		networkPrefix = byte(((decoded[0] & 0x3F) << 2) | (decoded[1] >> 6))
	} else {
		return nil, ErrInvalidVersion
	}

	if len(decoded) != prefixLen+32+2 {
		return nil, ErrInvalidAddress
	}

	return &AddressInfo{
		Address:   address,
		PublicKey: decoded[prefixLen : prefixLen+32],
		ChainID:   p.chainID,
		Type:      AddressTypeSS58,
		Version:   networkPrefix,
	}, nil
}
