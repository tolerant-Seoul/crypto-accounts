package address

import (
	"fmt"

	"golang.org/x/crypto/blake2b"
)

// Tezos address prefixes (Base58Check)
var (
	// Public key hash prefixes
	TezosEd25519PKHPrefix   = []byte{6, 161, 159}    // tz1
	TezosSecp256k1PKHPrefix = []byte{6, 161, 161}    // tz2
	TezosP256PKHPrefix      = []byte{6, 161, 164}    // tz3

	// Public key prefixes
	TezosEd25519PKPrefix   = []byte{13, 15, 37, 217} // edpk
	TezosSecp256k1PKPrefix = []byte{3, 254, 226, 86} // sppk
	TezosP256PKPrefix      = []byte{3, 178, 139, 127} // p2pk
)

// TezosKeyType represents the cryptographic curve used
type TezosKeyType int

const (
	TezosKeyEd25519 TezosKeyType = iota
	TezosKeySecp256k1
	TezosKeyP256
)

// TezosAddress generates Tezos (XTZ) addresses
type TezosAddress struct {
	keyType TezosKeyType
}

// NewTezosAddress creates a new Tezos address generator (default: Ed25519 -> tz1)
func NewTezosAddress() *TezosAddress {
	return &TezosAddress{keyType: TezosKeyEd25519}
}

// NewTezosAddressWithKeyType creates a Tezos address generator with specific key type
func NewTezosAddressWithKeyType(keyType TezosKeyType) *TezosAddress {
	return &TezosAddress{keyType: keyType}
}

// ChainID returns the chain identifier
func (t *TezosAddress) ChainID() ChainID {
	return ChainTezos
}

// Generate creates a Tezos address from a public key
// For Ed25519: 32-byte public key -> tz1 address
// For Secp256k1: 33-byte compressed public key -> tz2 address
// For P256: 33-byte compressed public key -> tz3 address
func (t *TezosAddress) Generate(publicKey []byte) (string, error) {
	var prefix []byte
	var expectedLen int

	switch t.keyType {
	case TezosKeyEd25519:
		prefix = TezosEd25519PKHPrefix
		expectedLen = 32
	case TezosKeySecp256k1:
		prefix = TezosSecp256k1PKHPrefix
		expectedLen = 33
	case TezosKeyP256:
		prefix = TezosP256PKHPrefix
		expectedLen = 33
	default:
		return "", fmt.Errorf("unsupported key type")
	}

	if len(publicKey) != expectedLen {
		return "", fmt.Errorf("invalid public key length for Tezos: expected %d, got %d", expectedLen, len(publicKey))
	}

	// Hash the public key with Blake2b-160
	hash := blake2b160(publicKey)

	// Encode with Base58Check using the appropriate prefix
	return Base58CheckEncodeWithPrefix(prefix, hash), nil
}

// GenerateTz1 creates a tz1 address from an Ed25519 public key (32 bytes)
func (t *TezosAddress) GenerateTz1(publicKey []byte) (string, error) {
	if len(publicKey) != 32 {
		return "", fmt.Errorf("Ed25519 public key must be 32 bytes")
	}
	hash := blake2b160(publicKey)
	return Base58CheckEncodeWithPrefix(TezosEd25519PKHPrefix, hash), nil
}

// GenerateTz2 creates a tz2 address from a Secp256k1 public key (33 bytes compressed)
func (t *TezosAddress) GenerateTz2(publicKey []byte) (string, error) {
	if len(publicKey) != 33 {
		return "", fmt.Errorf("Secp256k1 public key must be 33 bytes (compressed)")
	}
	hash := blake2b160(publicKey)
	return Base58CheckEncodeWithPrefix(TezosSecp256k1PKHPrefix, hash), nil
}

// GenerateTz3 creates a tz3 address from a P256 public key (33 bytes compressed)
func (t *TezosAddress) GenerateTz3(publicKey []byte) (string, error) {
	if len(publicKey) != 33 {
		return "", fmt.Errorf("P256 public key must be 33 bytes (compressed)")
	}
	hash := blake2b160(publicKey)
	return Base58CheckEncodeWithPrefix(TezosP256PKHPrefix, hash), nil
}

// Validate checks if a Tezos address is valid
func (t *TezosAddress) Validate(address string) bool {
	// Tezos addresses are 36 characters
	if len(address) != 36 {
		return false
	}

	// Check prefix
	prefix := address[:3]
	if prefix != "tz1" && prefix != "tz2" && prefix != "tz3" {
		return false
	}

	// Decode Base58
	decoded, err := Base58Decode(address)
	if err != nil {
		return false
	}

	// Should have 3-byte prefix + 20-byte hash + 4-byte checksum = 27 bytes
	if len(decoded) != 27 {
		return false
	}

	// Verify checksum
	payload := decoded[:23]
	checksum := decoded[23:]
	expectedChecksum := DoubleSHA256(payload)[:4]

	for i := 0; i < 4; i++ {
		if checksum[i] != expectedChecksum[i] {
			return false
		}
	}

	return true
}

// GetAddressType returns the type of Tezos address
func (t *TezosAddress) GetAddressType(address string) (string, error) {
	if len(address) < 3 {
		return "", ErrInvalidAddress
	}

	switch address[:3] {
	case "tz1":
		return "Ed25519", nil
	case "tz2":
		return "Secp256k1", nil
	case "tz3":
		return "P256", nil
	default:
		return "", ErrInvalidAddress
	}
}

// DecodeAddress decodes a Tezos address
func (t *TezosAddress) DecodeAddress(address string) (*AddressInfo, error) {
	if !t.Validate(address) {
		return nil, ErrInvalidAddress
	}

	decoded, err := Base58Decode(address)
	if err != nil {
		return nil, err
	}

	// 3-byte prefix + 20-byte hash + 4-byte checksum = 27 bytes
	if len(decoded) != 27 {
		return nil, ErrInvalidAddress
	}

	return &AddressInfo{
		Address:   address,
		PublicKey: decoded[3:23], // Skip 3-byte prefix, take 20-byte hash (exclude checksum)
		ChainID:   ChainTezos,
		Type:      AddressTypeBase58Check,
	}, nil
}

// blake2b160 computes Blake2b-160 hash (20 bytes)
func blake2b160(data []byte) []byte {
	h, err := blake2b.New(20, nil)
	if err != nil {
		// Fallback should never happen
		return nil
	}
	h.Write(data)
	return h.Sum(nil)
}

// Base58CheckEncodeWithPrefix encodes data with a prefix using Base58Check
func Base58CheckEncodeWithPrefix(prefix, data []byte) string {
	// Combine prefix and data
	payload := make([]byte, len(prefix)+len(data))
	copy(payload, prefix)
	copy(payload[len(prefix):], data)

	// Calculate checksum (double SHA256)
	checksum := DoubleSHA256(payload)[:4]

	// Combine payload and checksum
	result := make([]byte, len(payload)+4)
	copy(result, payload)
	copy(result[len(payload):], checksum)

	return Base58Encode(result)
}
