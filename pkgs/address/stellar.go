package address

import (
	"encoding/base32"
	"fmt"
)

// Stellar address type prefixes
const (
	StellarAccountPrefix byte = 6 << 3  // 'G' prefix (48)
	StellarSeedPrefix    byte = 18 << 3 // 'S' prefix (144)
	StellarMuxedPrefix   byte = 12 << 3 // 'M' prefix (96)
)

// Custom Base32 encoding for Stellar (no padding)
var stellarBase32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// StellarAddress generates Stellar addresses
// Stellar uses Ed25519 public keys encoded in Base32
type StellarAddress struct{}

// NewStellarAddress creates a new Stellar address generator
func NewStellarAddress() *StellarAddress {
	return &StellarAddress{}
}

// ChainID returns the chain identifier
func (s *StellarAddress) ChainID() ChainID {
	return ChainStellar
}

// Generate creates a Stellar address from a public key
// Public key should be 32 bytes (Ed25519 public key)
func (s *StellarAddress) Generate(publicKey []byte) (string, error) {
	if len(publicKey) != 32 {
		return "", fmt.Errorf("Stellar requires 32-byte Ed25519 public key, got %d bytes", len(publicKey))
	}

	// Create payload: version byte + public key
	payload := make([]byte, 33)
	payload[0] = StellarAccountPrefix
	copy(payload[1:], publicKey)

	// Calculate CRC16-XModem checksum
	checksum := crc16XModem(payload)

	// Create final data: payload + checksum (little-endian)
	final := make([]byte, 35)
	copy(final, payload)
	final[33] = byte(checksum & 0xFF)
	final[34] = byte(checksum >> 8)

	// Base32 encode
	return stellarBase32.EncodeToString(final), nil
}

// Validate checks if a Stellar address is valid
func (s *StellarAddress) Validate(address string) bool {
	// Must start with 'G' for account addresses
	if len(address) != 56 || address[0] != 'G' {
		return false
	}

	decoded, err := stellarBase32.DecodeString(address)
	if err != nil {
		return false
	}

	if len(decoded) != 35 {
		return false
	}

	// Verify version byte
	if decoded[0] != StellarAccountPrefix {
		return false
	}

	// Verify checksum
	payload := decoded[:33]
	expectedChecksum := crc16XModem(payload)
	actualChecksum := uint16(decoded[33]) | uint16(decoded[34])<<8

	return expectedChecksum == actualChecksum
}

// DecodeAddress decodes a Stellar address
func (s *StellarAddress) DecodeAddress(address string) (*AddressInfo, error) {
	if !s.Validate(address) {
		return nil, ErrInvalidAddress
	}

	decoded, _ := stellarBase32.DecodeString(address)

	return &AddressInfo{
		Address:   address,
		PublicKey: decoded[1:33],
		ChainID:   ChainStellar,
		Type:      AddressTypeBase32,
		Version:   decoded[0],
	}, nil
}

// crc16XModem calculates CRC16-XModem checksum
func crc16XModem(data []byte) uint16 {
	crc := uint16(0)
	polynomial := uint16(0x1021)

	for _, b := range data {
		crc ^= uint16(b) << 8
		for i := 0; i < 8; i++ {
			if crc&0x8000 != 0 {
				crc = (crc << 1) ^ polynomial
			} else {
				crc <<= 1
			}
		}
	}

	return crc
}
