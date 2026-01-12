package address

import (
	"fmt"
	"strings"
)

// EOS name character set (base31 without certain characters)
// a-z, 1-5, and . (period)
const eosNameCharset = ".12345abcdefghijklmnopqrstuvwxyz"

// EOSAddress generates EOS account names and public key representations
type EOSAddress struct{}

// NewEOSAddress creates a new EOS address generator
func NewEOSAddress() *EOSAddress {
	return &EOSAddress{}
}

// ChainID returns the chain identifier
func (e *EOSAddress) ChainID() ChainID {
	return ChainEOS
}

// Generate creates an EOS public key string from a secp256k1 public key
// Public key should be 33 bytes (compressed)
// Note: EOS account names are not derived from public keys - they are chosen by users
// This returns the EOS public key format (EOS + base58 encoded key)
func (e *EOSAddress) Generate(publicKey []byte) (string, error) {
	if len(publicKey) != 33 {
		return "", fmt.Errorf("invalid public key length: expected 33, got %d", len(publicKey))
	}

	// EOS public key format: EOS + base58(pubkey + ripemd160(pubkey)[:4])
	checksum := RIPEMD160Hash(publicKey)[:4]
	data := append(publicKey, checksum...)
	encoded := Base58Encode(data)

	return "EOS" + encoded, nil
}

// ValidateAccountName checks if an EOS account name is valid
func (e *EOSAddress) ValidateAccountName(name string) bool {
	// Account names are up to 12 characters
	if len(name) == 0 || len(name) > 12 {
		return false
	}

	// Must only contain valid characters
	for _, c := range name {
		if !strings.ContainsRune(eosNameCharset, c) {
			return false
		}
	}

	// Cannot start with a number
	if name[0] >= '1' && name[0] <= '5' {
		return false
	}

	return true
}

// Validate checks if an EOS address (public key or account name) is valid
func (e *EOSAddress) Validate(address string) bool {
	// Check if it's a public key format
	if strings.HasPrefix(address, "EOS") {
		return e.validatePublicKey(address)
	}

	// Check if it's a PUB_K1 format
	if strings.HasPrefix(address, "PUB_K1_") {
		return e.validatePubK1Key(address)
	}

	// Otherwise treat as account name
	return e.ValidateAccountName(address)
}

// validatePublicKey validates legacy EOS public key format
func (e *EOSAddress) validatePublicKey(address string) bool {
	if !strings.HasPrefix(address, "EOS") {
		return false
	}

	encoded := address[3:]
	if len(encoded) == 0 {
		return false
	}

	// Decode base58
	decoded, err := Base58Decode(encoded)
	if err != nil {
		return false
	}

	// Should be 33-byte pubkey + 4-byte checksum
	if len(decoded) != 37 {
		return false
	}

	// Verify checksum
	pubkey := decoded[:33]
	checksum := decoded[33:]
	expectedChecksum := RIPEMD160Hash(pubkey)[:4]

	for i := 0; i < 4; i++ {
		if checksum[i] != expectedChecksum[i] {
			return false
		}
	}

	return true
}

// validatePubK1Key validates new PUB_K1 format
func (e *EOSAddress) validatePubK1Key(address string) bool {
	if !strings.HasPrefix(address, "PUB_K1_") {
		return false
	}

	encoded := address[7:]
	if len(encoded) == 0 {
		return false
	}

	// Decode base58
	decoded, err := Base58Decode(encoded)
	if err != nil {
		return false
	}

	// Should be 33-byte pubkey + 4-byte checksum
	if len(decoded) != 37 {
		return false
	}

	// For PUB_K1_, checksum is ripemd160("K1" + pubkey)[:4]
	pubkey := decoded[:33]
	checksum := decoded[33:]

	checksumInput := append([]byte("K1"), pubkey...)
	expectedChecksum := RIPEMD160Hash(checksumInput)[:4]

	for i := 0; i < 4; i++ {
		if checksum[i] != expectedChecksum[i] {
			return false
		}
	}

	return true
}

// GetAddressType returns the type of EOS address
func (e *EOSAddress) GetAddressType(address string) (string, error) {
	if strings.HasPrefix(address, "EOS") {
		return "Legacy Public Key (EOS)", nil
	}
	if strings.HasPrefix(address, "PUB_K1_") {
		return "Public Key (K1/secp256k1)", nil
	}
	if strings.HasPrefix(address, "PUB_R1_") {
		return "Public Key (R1/secp256r1)", nil
	}
	if e.ValidateAccountName(address) {
		return "Account Name", nil
	}
	return "", ErrInvalidAddress
}

// DecodeAddress decodes an EOS address
func (e *EOSAddress) DecodeAddress(address string) (*AddressInfo, error) {
	if !e.Validate(address) {
		return nil, ErrInvalidAddress
	}

	var publicKey []byte

	if strings.HasPrefix(address, "EOS") {
		encoded := address[3:]
		decoded, err := Base58Decode(encoded)
		if err != nil {
			return nil, err
		}
		publicKey = decoded[:33]
	} else if strings.HasPrefix(address, "PUB_K1_") {
		encoded := address[7:]
		decoded, err := Base58Decode(encoded)
		if err != nil {
			return nil, err
		}
		publicKey = decoded[:33]
	}

	return &AddressInfo{
		Address:   address,
		PublicKey: publicKey, // May be nil for account names
		ChainID:   ChainEOS,
		Type:      AddressTypeBase58,
	}, nil
}

// GeneratePubK1Key creates an EOS public key in PUB_K1 format
func (e *EOSAddress) GeneratePubK1Key(publicKey []byte) (string, error) {
	if len(publicKey) != 33 {
		return "", fmt.Errorf("invalid public key length: expected 33, got %d", len(publicKey))
	}

	// Checksum is ripemd160("K1" + pubkey)[:4]
	checksumInput := append([]byte("K1"), publicKey...)
	checksum := RIPEMD160Hash(checksumInput)[:4]

	data := append(publicKey, checksum...)
	encoded := Base58Encode(data)

	return "PUB_K1_" + encoded, nil
}

// NameToUint64 converts an EOS account name to uint64
func (e *EOSAddress) NameToUint64(name string) (uint64, error) {
	if !e.ValidateAccountName(name) {
		return 0, fmt.Errorf("invalid account name")
	}

	var value uint64
	for i := 0; i < len(name) && i < 12; i++ {
		c := name[i]
		var charValue uint64
		if c == '.' {
			charValue = 0
		} else if c >= '1' && c <= '5' {
			charValue = uint64(c-'1') + 1
		} else if c >= 'a' && c <= 'z' {
			charValue = uint64(c-'a') + 6
		}

		if i < 12 {
			value = (value << 5) | charValue
		}
	}

	// Pad remaining bits
	if len(name) < 12 {
		value <<= 5 * (12 - len(name))
	}

	return value, nil
}

