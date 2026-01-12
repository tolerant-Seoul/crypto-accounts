package address

import (
	"fmt"

	"golang.org/x/crypto/blake2b"
)

// Filecoin protocol indicators
const (
	FilecoinProtocolID        = 0 // ID addresses (f0)
	FilecoinProtocolSecp256k1 = 1 // Secp256k1 addresses (f1)
	FilecoinProtocolActor     = 2 // Actor addresses (f2)
	FilecoinProtocolBLS       = 3 // BLS addresses (f3)
)

// Filecoin Base32 alphabet (lowercase, no padding)
const filecoinBase32Alphabet = "abcdefghijklmnopqrstuvwxyz234567"

// FilecoinAddress generates Filecoin (FIL) addresses
type FilecoinAddress struct {
	testnet bool
}

// NewFilecoinAddress creates a new Filecoin address generator for mainnet
func NewFilecoinAddress() *FilecoinAddress {
	return &FilecoinAddress{testnet: false}
}

// NewFilecoinTestnetAddress creates a new Filecoin address generator for testnet
func NewFilecoinTestnetAddress() *FilecoinAddress {
	return &FilecoinAddress{testnet: true}
}

// ChainID returns the chain identifier
func (f *FilecoinAddress) ChainID() ChainID {
	return ChainFilecoin
}

// Generate creates a Filecoin f1 address from a secp256k1 public key
// Public key should be 65 bytes (uncompressed)
func (f *FilecoinAddress) Generate(publicKey []byte) (string, error) {
	if len(publicKey) != 65 {
		return "", fmt.Errorf("invalid public key length: expected 65 (uncompressed), got %d", len(publicKey))
	}

	return f.F1Address(publicKey)
}

// F1Address creates an f1 (secp256k1) address from an uncompressed public key
func (f *FilecoinAddress) F1Address(publicKey []byte) (string, error) {
	if len(publicKey) != 65 {
		return "", fmt.Errorf("invalid public key length for f1: expected 65, got %d", len(publicKey))
	}

	// Hash the public key with Blake2b-160
	hash := filecoinBlake2b160(publicKey)

	// Calculate checksum: Blake2b-32 of (protocol + hash)
	checksumInput := make([]byte, 1+len(hash))
	checksumInput[0] = FilecoinProtocolSecp256k1
	copy(checksumInput[1:], hash)
	checksum := filecoinBlake2b32(checksumInput)

	// Combine hash and checksum
	payload := append(hash, checksum...)

	// Encode with base32
	encoded := filecoinBase32Encode(payload)

	// Add prefix
	prefix := f.getPrefix()
	return fmt.Sprintf("%s1%s", prefix, encoded), nil
}

// getPrefix returns the network prefix
func (f *FilecoinAddress) getPrefix() string {
	if f.testnet {
		return "t"
	}
	return "f"
}

// Validate checks if a Filecoin address is valid
func (f *FilecoinAddress) Validate(address string) bool {
	if len(address) < 3 {
		return false
	}

	// Check network prefix
	prefix := f.getPrefix()
	if address[0] != prefix[0] {
		return false
	}

	// Check protocol
	protocol := address[1]
	if protocol < '0' || protocol > '3' {
		return false
	}

	// For f1 addresses (secp256k1)
	if protocol == '1' {
		return f.validateF1Address(address)
	}

	// For other protocols, just do basic validation
	return len(address) > 2
}

// validateF1Address validates an f1 address
func (f *FilecoinAddress) validateF1Address(address string) bool {
	if len(address) < 3 {
		return false
	}

	// Decode the base32 payload
	encoded := address[2:]
	decoded, err := filecoinBase32Decode(encoded)
	if err != nil {
		return false
	}

	// Should be 20-byte hash + 4-byte checksum = 24 bytes
	if len(decoded) != 24 {
		return false
	}

	hash := decoded[:20]
	checksum := decoded[20:]

	// Verify checksum
	checksumInput := make([]byte, 1+20)
	checksumInput[0] = FilecoinProtocolSecp256k1
	copy(checksumInput[1:], hash)
	expectedChecksum := filecoinBlake2b32(checksumInput)

	for i := 0; i < 4; i++ {
		if checksum[i] != expectedChecksum[i] {
			return false
		}
	}

	return true
}

// GetAddressType returns the type of Filecoin address
func (f *FilecoinAddress) GetAddressType(address string) (string, error) {
	if len(address) < 2 {
		return "", ErrInvalidAddress
	}

	protocol := address[1]
	switch protocol {
	case '0':
		return "ID (f0)", nil
	case '1':
		return "Secp256k1 (f1)", nil
	case '2':
		return "Actor (f2)", nil
	case '3':
		return "BLS (f3)", nil
	default:
		return "", ErrInvalidAddress
	}
}

// DecodeAddress decodes a Filecoin address
func (f *FilecoinAddress) DecodeAddress(address string) (*AddressInfo, error) {
	if !f.Validate(address) {
		return nil, ErrInvalidAddress
	}

	if address[1] != '1' {
		return nil, fmt.Errorf("only f1 addresses are fully supported")
	}

	encoded := address[2:]
	decoded, err := filecoinBase32Decode(encoded)
	if err != nil {
		return nil, err
	}

	return &AddressInfo{
		Address:   address,
		PublicKey: decoded[:20], // 20-byte hash
		ChainID:   ChainFilecoin,
		Type:      AddressTypeBase32,
		Version:   FilecoinProtocolSecp256k1,
	}, nil
}

// filecoinBlake2b160 computes Blake2b-160 hash
func filecoinBlake2b160(data []byte) []byte {
	h, err := blake2b.New(20, nil)
	if err != nil {
		return nil
	}
	h.Write(data)
	return h.Sum(nil)
}

// filecoinBlake2b32 computes Blake2b-32 (4 bytes) for checksum
func filecoinBlake2b32(data []byte) []byte {
	h, err := blake2b.New(4, nil)
	if err != nil {
		return nil
	}
	h.Write(data)
	return h.Sum(nil)
}

// filecoinBase32Encode encodes data to base32 (lowercase, no padding)
func filecoinBase32Encode(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	result := make([]byte, 0, (len(data)*8+4)/5)
	var carry uint32
	var bits uint

	for _, b := range data {
		carry = (carry << 8) | uint32(b)
		bits += 8

		for bits >= 5 {
			bits -= 5
			result = append(result, filecoinBase32Alphabet[(carry>>bits)&0x1F])
		}
	}

	if bits > 0 {
		result = append(result, filecoinBase32Alphabet[(carry<<(5-bits))&0x1F])
	}

	return string(result)
}

// filecoinBase32Decode decodes base32 to bytes
func filecoinBase32Decode(str string) ([]byte, error) {
	if len(str) == 0 {
		return []byte{}, nil
	}

	// Build reverse lookup
	alphabet := make(map[byte]byte)
	for i := 0; i < len(filecoinBase32Alphabet); i++ {
		alphabet[filecoinBase32Alphabet[i]] = byte(i)
	}

	var carry uint64
	var bits uint

	result := make([]byte, 0, len(str)*5/8)

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

	return result, nil
}
