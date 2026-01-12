package address

import (
	"fmt"
	"strings"
)

// Kaspa address types
const (
	KaspaAddressTypeP2PK  = 0x00 // Pay to Public Key (ECDSA)
	KaspaAddressTypeP2PKE = 0x01 // Pay to Public Key (ECDSA) - alternative
	KaspaAddressTypeP2SH  = 0x08 // Pay to Script Hash
)

// KaspaAddress generates Kaspa (KAS) addresses
type KaspaAddress struct {
	testnet bool
}

// NewKaspaAddress creates a new Kaspa address generator for mainnet
func NewKaspaAddress() *KaspaAddress {
	return &KaspaAddress{testnet: false}
}

// NewKaspaTestnetAddress creates a new Kaspa address generator for testnet
func NewKaspaTestnetAddress() *KaspaAddress {
	return &KaspaAddress{testnet: true}
}

// ChainID returns the chain identifier
func (k *KaspaAddress) ChainID() ChainID {
	return ChainKaspa
}

// Generate creates a Kaspa address from a public key
// Public key should be 33 bytes (compressed secp256k1)
func (k *KaspaAddress) Generate(publicKey []byte) (string, error) {
	if len(publicKey) != 33 {
		return "", fmt.Errorf("invalid public key length: expected 33, got %d", len(publicKey))
	}

	return k.P2PK(publicKey)
}

// P2PK creates a Pay-to-Public-Key address
func (k *KaspaAddress) P2PK(publicKey []byte) (string, error) {
	if len(publicKey) != 33 {
		return "", fmt.Errorf("invalid public key length for P2PK")
	}

	// Kaspa uses the public key directly (not hashed) for P2PK addresses
	// Format: version byte (0x00) + 32-byte x-coordinate
	// We extract x-coordinate from compressed public key (skip first byte)
	xCoord := publicKey[1:33]

	// Version byte for P2PK
	data := make([]byte, 1+32)
	data[0] = KaspaAddressTypeP2PK
	copy(data[1:], xCoord)

	prefix := k.getPrefix()
	return Bech32Encode(prefix, data, Bech32Standard)
}

// P2SH creates a Pay-to-Script-Hash address
func (k *KaspaAddress) P2SH(scriptHash []byte) (string, error) {
	if len(scriptHash) != 32 {
		return "", fmt.Errorf("invalid script hash length: expected 32, got %d", len(scriptHash))
	}

	// Version byte for P2SH
	data := make([]byte, 1+32)
	data[0] = KaspaAddressTypeP2SH
	copy(data[1:], scriptHash)

	prefix := k.getPrefix()
	return Bech32Encode(prefix, data, Bech32Standard)
}

// getPrefix returns the HRP (Human-Readable Part) for addresses
func (k *KaspaAddress) getPrefix() string {
	if k.testnet {
		return "kaspatest"
	}
	return "kaspa"
}

// Validate checks if a Kaspa address is valid
func (k *KaspaAddress) Validate(address string) bool {
	// Check prefix
	prefix := k.getPrefix()
	if !strings.HasPrefix(address, prefix+":") {
		return false
	}

	// Try to decode
	hrp, data, _, err := Bech32Decode(address)
	if err != nil {
		return false
	}

	// Verify HRP
	if hrp != prefix {
		return false
	}

	// Data should be 33 bytes (1 version + 32 payload)
	if len(data) != 33 {
		return false
	}

	// Verify version byte
	version := data[0]
	if version != KaspaAddressTypeP2PK && version != KaspaAddressTypeP2PKE && version != KaspaAddressTypeP2SH {
		return false
	}

	return true
}

// GetAddressType returns the type of Kaspa address
func (k *KaspaAddress) GetAddressType(address string) (string, error) {
	if !k.Validate(address) {
		return "", ErrInvalidAddress
	}

	_, data, _, err := Bech32Decode(address)
	if err != nil {
		return "", err
	}

	switch data[0] {
	case KaspaAddressTypeP2PK:
		return "P2PK (ECDSA)", nil
	case KaspaAddressTypeP2PKE:
		return "P2PK (ECDSA alternative)", nil
	case KaspaAddressTypeP2SH:
		return "P2SH", nil
	default:
		return "unknown", nil
	}
}

// DecodeAddress decodes a Kaspa address
func (k *KaspaAddress) DecodeAddress(address string) (*AddressInfo, error) {
	if !k.Validate(address) {
		return nil, ErrInvalidAddress
	}

	_, data, _, err := Bech32Decode(address)
	if err != nil {
		return nil, err
	}

	return &AddressInfo{
		Address:   address,
		PublicKey: data[1:], // Skip version byte
		ChainID:   ChainKaspa,
		Type:      AddressTypeBech32,
		Version:   data[0],
	}, nil
}
