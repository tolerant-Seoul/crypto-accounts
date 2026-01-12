package address

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"strings"
)

// ICP Principal types
const (
	ICPPrincipalSelfAuthenticating = 0x02 // Self-authenticating principal (from public key)
	ICPPrincipalAnonymous          = 0x04 // Anonymous principal
)

// ICPAddress generates Internet Computer (ICP) Principal IDs
type ICPAddress struct{}

// NewICPAddress creates a new ICP address generator
func NewICPAddress() *ICPAddress {
	return &ICPAddress{}
}

// ChainID returns the chain identifier
func (i *ICPAddress) ChainID() ChainID {
	return ChainICP
}

// Generate creates an ICP Principal ID from a public key
// Supports Ed25519 (32 bytes) or Secp256k1 (33 bytes compressed)
func (i *ICPAddress) Generate(publicKey []byte) (string, error) {
	if len(publicKey) != 32 && len(publicKey) != 33 {
		return "", fmt.Errorf("invalid public key length: expected 32 (Ed25519) or 33 (Secp256k1), got %d", len(publicKey))
	}

	// Create DER-encoded public key representation
	var derKey []byte
	if len(publicKey) == 32 {
		// Ed25519: wrap with DER header
		derKey = i.wrapEd25519PublicKey(publicKey)
	} else {
		// Secp256k1: wrap with DER header
		derKey = i.wrapSecp256k1PublicKey(publicKey)
	}

	// SHA-224 hash of the DER-encoded public key
	hash := sha256.Sum224(derKey)

	// Append self-authenticating type byte
	principalBytes := make([]byte, 29)
	copy(principalBytes, hash[:])
	principalBytes[28] = ICPPrincipalSelfAuthenticating

	// Encode as textual representation
	return i.encodePrincipal(principalBytes), nil
}

// wrapEd25519PublicKey wraps an Ed25519 public key with DER encoding
func (i *ICPAddress) wrapEd25519PublicKey(publicKey []byte) []byte {
	// DER header for Ed25519 public key
	derHeader := []byte{
		0x30, 0x2a, // SEQUENCE, length 42
		0x30, 0x05, // SEQUENCE, length 5
		0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112 (Ed25519)
		0x03, 0x21, 0x00, // BIT STRING, length 33, no unused bits
	}
	return append(derHeader, publicKey...)
}

// wrapSecp256k1PublicKey wraps a secp256k1 public key with DER encoding
func (i *ICPAddress) wrapSecp256k1PublicKey(publicKey []byte) []byte {
	// DER header for secp256k1 public key
	derHeader := []byte{
		0x30, 0x56, // SEQUENCE, length 86
		0x30, 0x10, // SEQUENCE, length 16
		0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, // OID 1.2.840.10045.2.1 (ecPublicKey)
		0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x0a, // OID 1.3.132.0.10 (secp256k1)
		0x03, 0x42, 0x00, // BIT STRING, length 66, no unused bits
	}
	return append(derHeader, publicKey...)
}

// encodePrincipal encodes principal bytes to textual representation
func (i *ICPAddress) encodePrincipal(data []byte) string {
	// Calculate CRC32 checksum
	crc := i.crc32(data)

	// Prepend checksum to data
	withChecksum := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(withChecksum, crc)
	copy(withChecksum[4:], data)

	// Base32 encode (lowercase, no padding)
	encoded := i.base32Encode(withChecksum)

	// Group into 5-character segments separated by dashes
	return i.groupWithDashes(encoded, 5)
}

// crc32 calculates CRC32 checksum for ICP
func (i *ICPAddress) crc32(data []byte) uint32 {
	// ICP uses CRC-32 with polynomial 0x04C11DB7 (ISO 3309)
	var crc uint32 = 0xFFFFFFFF
	for _, b := range data {
		crc ^= uint32(b) << 24
		for j := 0; j < 8; j++ {
			if crc&0x80000000 != 0 {
				crc = (crc << 1) ^ 0x04C11DB7
			} else {
				crc <<= 1
			}
		}
	}
	return crc
}

// base32Encode encodes data to base32 (lowercase, no padding)
func (i *ICPAddress) base32Encode(data []byte) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz234567"
	if len(data) == 0 {
		return ""
	}

	result := make([]byte, 0, (len(data)*8+4)/5)
	var carry uint64
	var bits uint

	for _, b := range data {
		carry = (carry << 8) | uint64(b)
		bits += 8

		for bits >= 5 {
			bits -= 5
			result = append(result, alphabet[(carry>>bits)&0x1F])
		}
	}

	if bits > 0 {
		result = append(result, alphabet[(carry<<(5-bits))&0x1F])
	}

	return string(result)
}

// groupWithDashes groups string into segments separated by dashes
func (i *ICPAddress) groupWithDashes(s string, groupSize int) string {
	var groups []string
	for len(s) > 0 {
		end := groupSize
		if end > len(s) {
			end = len(s)
		}
		groups = append(groups, s[:end])
		s = s[end:]
	}
	return strings.Join(groups, "-")
}

// Validate checks if an ICP Principal ID is valid
func (i *ICPAddress) Validate(address string) bool {
	// Remove dashes
	cleaned := strings.ReplaceAll(address, "-", "")

	// Decode base32
	decoded, err := i.base32Decode(cleaned)
	if err != nil {
		return false
	}

	// Minimum: 4-byte checksum + 1-byte principal
	if len(decoded) < 5 {
		return false
	}

	// Extract checksum and data
	checksum := binary.BigEndian.Uint32(decoded[:4])
	data := decoded[4:]

	// Verify checksum
	expectedChecksum := i.crc32(data)
	return checksum == expectedChecksum
}

// base32Decode decodes base32 to bytes
func (i *ICPAddress) base32Decode(str string) ([]byte, error) {
	const alphabet = "abcdefghijklmnopqrstuvwxyz234567"
	if len(str) == 0 {
		return []byte{}, nil
	}

	// Build reverse lookup
	lookup := make(map[byte]byte)
	for j := 0; j < len(alphabet); j++ {
		lookup[alphabet[j]] = byte(j)
	}

	var carry uint64
	var bits uint
	result := make([]byte, 0, len(str)*5/8)

	for j := 0; j < len(str); j++ {
		c := str[j]
		val, ok := lookup[c]
		if !ok {
			return nil, fmt.Errorf("invalid character: %c", c)
		}

		carry = (carry << 5) | uint64(val)
		bits += 5

		for bits >= 8 {
			bits -= 8
			result = append(result, byte(carry>>bits))
		}
	}

	return result, nil
}

// GetAddressType returns the type of ICP address
func (i *ICPAddress) GetAddressType(address string) (string, error) {
	cleaned := strings.ReplaceAll(address, "-", "")
	decoded, err := i.base32Decode(cleaned)
	if err != nil {
		return "", ErrInvalidAddress
	}

	if len(decoded) < 5 {
		return "", ErrInvalidAddress
	}

	data := decoded[4:]
	lastByte := data[len(data)-1]

	switch lastByte {
	case ICPPrincipalSelfAuthenticating:
		return "Self-Authenticating Principal", nil
	case ICPPrincipalAnonymous:
		return "Anonymous Principal", nil
	default:
		return "Opaque Principal", nil
	}
}

// DecodeAddress decodes an ICP Principal ID
func (i *ICPAddress) DecodeAddress(address string) (*AddressInfo, error) {
	if !i.Validate(address) {
		return nil, ErrInvalidAddress
	}

	cleaned := strings.ReplaceAll(address, "-", "")
	decoded, err := i.base32Decode(cleaned)
	if err != nil {
		return nil, err
	}

	return &AddressInfo{
		Address:   address,
		PublicKey: decoded[4:], // Principal bytes (without checksum)
		ChainID:   ChainICP,
		Type:      AddressTypeBase32,
	}, nil
}
