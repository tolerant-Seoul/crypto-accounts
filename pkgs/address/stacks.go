package address

import (
	"crypto/sha256"
	"fmt"
	"strings"
)

// Stacks address version bytes
const (
	StacksMainnetSingleSig = 22  // P (mainnet single-sig)
	StacksMainnetMultiSig  = 20  // M (mainnet multi-sig)
	StacksTestnetSingleSig = 26  // T (testnet single-sig)
	StacksTestnetMultiSig  = 21  // N (testnet multi-sig)
)

// C32 alphabet (Crockford's Base32 variant)
const c32Alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// StacksAddress generates Stacks (STX) addresses
type StacksAddress struct {
	testnet bool
}

// NewStacksAddress creates a new Stacks address generator for mainnet
func NewStacksAddress() *StacksAddress {
	return &StacksAddress{testnet: false}
}

// NewStacksTestnetAddress creates a new Stacks address generator for testnet
func NewStacksTestnetAddress() *StacksAddress {
	return &StacksAddress{testnet: true}
}

// ChainID returns the chain identifier
func (s *StacksAddress) ChainID() ChainID {
	return ChainStacks
}

// Generate creates a Stacks address from a public key
// Public key should be 33 bytes (compressed secp256k1)
func (s *StacksAddress) Generate(publicKey []byte) (string, error) {
	if len(publicKey) != 33 {
		return "", fmt.Errorf("invalid public key length: expected 33, got %d", len(publicKey))
	}

	// Hash160 = RIPEMD160(SHA256(publicKey))
	hash := Hash160(publicKey)

	// Get version byte
	var version byte
	if s.testnet {
		version = StacksTestnetSingleSig
	} else {
		version = StacksMainnetSingleSig
	}

	// Encode with c32check
	return c32CheckEncode(version, hash)
}

// Validate checks if a Stacks address is valid
func (s *StacksAddress) Validate(address string) bool {
	// Must start with 'S' prefix
	if !strings.HasPrefix(address, "S") {
		return false
	}

	// Try to decode
	version, _, err := c32CheckDecode(address)
	if err != nil {
		return false
	}

	// Verify version based on network
	if s.testnet {
		return version == StacksTestnetSingleSig || version == StacksTestnetMultiSig
	}
	return version == StacksMainnetSingleSig || version == StacksMainnetMultiSig
}

// GetAddressType returns the type of Stacks address
func (s *StacksAddress) GetAddressType(address string) (string, error) {
	version, _, err := c32CheckDecode(address)
	if err != nil {
		return "", ErrInvalidAddress
	}

	switch version {
	case StacksMainnetSingleSig:
		return "Mainnet Single-sig (P)", nil
	case StacksMainnetMultiSig:
		return "Mainnet Multi-sig (M)", nil
	case StacksTestnetSingleSig:
		return "Testnet Single-sig (T)", nil
	case StacksTestnetMultiSig:
		return "Testnet Multi-sig (N)", nil
	default:
		return "unknown", nil
	}
}

// DecodeAddress decodes a Stacks address
func (s *StacksAddress) DecodeAddress(address string) (*AddressInfo, error) {
	version, hash, err := c32CheckDecode(address)
	if err != nil {
		return nil, err
	}

	return &AddressInfo{
		Address:   address,
		PublicKey: hash,
		ChainID:   ChainStacks,
		Type:      AddressTypeBase58Check, // c32check is similar to Base58Check
		Version:   version,
	}, nil
}

// c32CheckEncode encodes data using c32check format
func c32CheckEncode(version byte, data []byte) (string, error) {
	// Calculate checksum: SHA256(SHA256(version + data))
	payload := make([]byte, 1+len(data))
	payload[0] = version
	copy(payload[1:], data)

	hash1 := sha256.Sum256(payload)
	hash2 := sha256.Sum256(hash1[:])
	checksum := hash2[:4]

	// Combine payload and checksum
	full := append(payload, checksum...)

	// Encode to c32
	encoded := c32Encode(full[1:]) // Skip version for encoding

	// Add version character prefix
	versionChar := c32Alphabet[version]

	return "S" + string(versionChar) + encoded, nil
}

// c32CheckDecode decodes a c32check encoded string
func c32CheckDecode(address string) (byte, []byte, error) {
	if len(address) < 3 {
		return 0, nil, fmt.Errorf("address too short")
	}

	// Remove 'S' prefix
	if address[0] != 'S' {
		return 0, nil, fmt.Errorf("invalid prefix")
	}

	// Get version from second character
	versionChar := address[1]
	version := byte(strings.IndexByte(c32Alphabet, versionChar))
	if version == 255 {
		return 0, nil, fmt.Errorf("invalid version character")
	}

	// Decode the rest
	decoded, err := c32Decode(address[2:])
	if err != nil {
		return 0, nil, err
	}

	// Need at least 4 bytes for checksum
	if len(decoded) < 4 {
		return 0, nil, fmt.Errorf("decoded data too short")
	}

	// Split payload and checksum
	data := decoded[:len(decoded)-4]
	checksum := decoded[len(decoded)-4:]

	// Verify checksum
	payload := make([]byte, 1+len(data))
	payload[0] = version
	copy(payload[1:], data)

	hash1 := sha256.Sum256(payload)
	hash2 := sha256.Sum256(hash1[:])
	expectedChecksum := hash2[:4]

	for i := 0; i < 4; i++ {
		if checksum[i] != expectedChecksum[i] {
			return 0, nil, fmt.Errorf("invalid checksum")
		}
	}

	return version, data, nil
}

// c32Encode encodes bytes to c32 string
func c32Encode(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	// Convert bytes to base32
	result := make([]byte, 0, len(data)*8/5+1)

	var carry uint32
	var bits uint

	for _, b := range data {
		carry = (carry << 8) | uint32(b)
		bits += 8

		for bits >= 5 {
			bits -= 5
			result = append(result, c32Alphabet[(carry>>bits)&0x1F])
		}
	}

	if bits > 0 {
		result = append(result, c32Alphabet[(carry<<(5-bits))&0x1F])
	}

	// Remove leading zeros but preserve at least one character
	start := 0
	for start < len(result)-1 && result[start] == '0' {
		start++
	}

	// Add leading zeros for leading zero bytes
	for _, b := range data {
		if b != 0 {
			break
		}
		result = append([]byte{'0'}, result...)
	}

	return string(result[start:])
}

// c32Decode decodes a c32 string to bytes
func c32Decode(str string) ([]byte, error) {
	if len(str) == 0 {
		return []byte{}, nil
	}

	// Build reverse alphabet lookup
	alphabet := make(map[byte]byte)
	for i := 0; i < len(c32Alphabet); i++ {
		alphabet[c32Alphabet[i]] = byte(i)
	}
	// Handle lowercase
	for i := 0; i < len(c32Alphabet); i++ {
		if c32Alphabet[i] >= 'A' && c32Alphabet[i] <= 'Z' {
			alphabet[c32Alphabet[i]+32] = byte(i)
		}
	}

	// Count leading zeros
	leadingZeros := 0
	for _, c := range str {
		if c == '0' {
			leadingZeros++
		} else {
			break
		}
	}

	// Convert from base32 to bytes
	var carry uint64
	var bits uint

	result := make([]byte, 0, len(str)*5/8+1)

	for i := 0; i < len(str); i++ {
		val, ok := alphabet[str[i]]
		if !ok {
			return nil, fmt.Errorf("invalid character: %c", str[i])
		}

		carry = (carry << 5) | uint64(val)
		bits += 5

		for bits >= 8 {
			bits -= 8
			result = append(result, byte(carry>>bits))
		}
	}

	// Add leading zero bytes
	zeros := make([]byte, leadingZeros)
	result = append(zeros, result...)

	return result, nil
}
