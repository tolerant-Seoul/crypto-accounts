package address

import (
	"fmt"
)

// Ripple address version
const (
	RippleAccountPrefix byte = 0x00 // Addresses start with 'r'
)

// Ripple-specific Base58 encoder
var rippleBase58 = NewBase58Encoder(RippleAlphabet)

// RippleAddress generates Ripple (XRP) addresses
type RippleAddress struct{}

// NewRippleAddress creates a new Ripple address generator
func NewRippleAddress() *RippleAddress {
	return &RippleAddress{}
}

// ChainID returns the chain identifier
func (r *RippleAddress) ChainID() ChainID {
	return ChainRipple
}

// Generate creates a Ripple address from a public key
// Public key should be 33 bytes (compressed secp256k1)
func (r *RippleAddress) Generate(publicKey []byte) (string, error) {
	if len(publicKey) != 33 {
		return "", fmt.Errorf("Ripple requires 33-byte compressed public key, got %d bytes", len(publicKey))
	}

	// 1. SHA256 then RIPEMD160 to create Account ID
	accountID := Hash160(publicKey)

	// 2. Add version prefix (0x00)
	payload := make([]byte, 21)
	payload[0] = RippleAccountPrefix
	copy(payload[1:], accountID)

	// 3. Calculate checksum (double SHA256, first 4 bytes)
	checksum := DoubleSHA256(payload)[:4]

	// 4. Append checksum and encode with Ripple's Base58
	final := append(payload, checksum...)

	return rippleBase58.Encode(final), nil
}

// Validate checks if a Ripple address is valid
func (r *RippleAddress) Validate(address string) bool {
	// Must start with 'r'
	if len(address) == 0 || address[0] != 'r' {
		return false
	}

	decoded, err := rippleBase58.Decode(address)
	if err != nil {
		return false
	}

	if len(decoded) != 25 {
		return false
	}

	// Verify version byte
	if decoded[0] != RippleAccountPrefix {
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

// DecodeAddress decodes a Ripple address
func (r *RippleAddress) DecodeAddress(address string) (*AddressInfo, error) {
	if !r.Validate(address) {
		return nil, ErrInvalidAddress
	}

	decoded, _ := rippleBase58.Decode(address)

	return &AddressInfo{
		Address:   address,
		PublicKey: decoded[1:21], // Account ID without version and checksum
		ChainID:   ChainRipple,
		Type:      AddressTypeBase58Check,
		Version:   decoded[0],
	}, nil
}
