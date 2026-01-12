package address

import (
	"crypto/sha256"
	"fmt"

	"golang.org/x/crypto/blake2b"
)

// Cardano address types (Shelley era)
const (
	// Address type nibbles (upper 4 bits of first byte)
	CardanoBaseAddress       = 0x00 // Payment key hash + Stake key hash
	CardanoScriptAddress     = 0x01 // Script hash + Stake key hash
	CardanoBaseScriptAddress = 0x02 // Payment key hash + Script hash
	CardanoScriptScriptAddr  = 0x03 // Script hash + Script hash
	CardanoPointerAddress    = 0x04 // Payment key hash + Pointer
	CardanoScriptPointer     = 0x05 // Script hash + Pointer
	CardanoEnterpriseAddress = 0x06 // Payment key hash only (no staking)
	CardanoEnterpriseScript  = 0x07 // Script hash only (no staking)
	CardanoRewardAddress     = 0x0E // Stake key hash (for rewards)
	CardanoRewardScript      = 0x0F // Script hash (for rewards)

	// Network tags (lower 4 bits of first byte)
	CardanoMainnet = 0x01
	CardanoTestnet = 0x00

	// HRPs (Human Readable Parts)
	CardanoMainnetHRP        = "addr"
	CardanoTestnetHRP        = "addr_test"
	CardanoMainnetStakeHRP   = "stake"
	CardanoTestnetStakeHRP   = "stake_test"

	// Key hash size
	CardanoKeyHashSize = 28
)

// CardanoAddress generates Cardano (ADA) addresses
type CardanoAddress struct {
	testnet bool
}

// NewCardanoAddress creates a new Cardano address generator for mainnet
func NewCardanoAddress() *CardanoAddress {
	return &CardanoAddress{testnet: false}
}

// NewCardanoTestnetAddress creates a new Cardano address generator for testnet
func NewCardanoTestnetAddress() *CardanoAddress {
	return &CardanoAddress{testnet: true}
}

// ChainID returns the chain identifier
func (c *CardanoAddress) ChainID() ChainID {
	return ChainCardano
}

// Generate creates a Cardano enterprise address from an Ed25519 public key
// Public key should be 32 bytes (Ed25519)
// This generates an enterprise address (no staking capability)
func (c *CardanoAddress) Generate(publicKey []byte) (string, error) {
	if len(publicKey) != 32 {
		return "", fmt.Errorf("Cardano requires 32-byte Ed25519 public key, got %d bytes", len(publicKey))
	}

	// Generate enterprise address (simpler, no staking)
	return c.GenerateEnterpriseAddress(publicKey)
}

// GenerateEnterpriseAddress creates an enterprise address (payment only, no staking)
func (c *CardanoAddress) GenerateEnterpriseAddress(publicKey []byte) (string, error) {
	if len(publicKey) != 32 {
		return "", fmt.Errorf("Cardano requires 32-byte Ed25519 public key")
	}

	// Hash the public key using Blake2b-224
	keyHash := blake2b224(publicKey)

	// Build address bytes
	// First byte: address type (upper nibble) | network tag (lower nibble)
	var header byte
	if c.testnet {
		header = (CardanoEnterpriseAddress << 4) | CardanoTestnet
	} else {
		header = (CardanoEnterpriseAddress << 4) | CardanoMainnet
	}

	addressBytes := make([]byte, 1+CardanoKeyHashSize)
	addressBytes[0] = header
	copy(addressBytes[1:], keyHash)

	// Encode with Bech32
	hrp := CardanoMainnetHRP
	if c.testnet {
		hrp = CardanoTestnetHRP
	}

	return Bech32Encode(hrp, addressBytes, Bech32Standard)
}

// GenerateBaseAddress creates a base address (payment + staking)
func (c *CardanoAddress) GenerateBaseAddress(paymentKey, stakeKey []byte) (string, error) {
	if len(paymentKey) != 32 || len(stakeKey) != 32 {
		return "", fmt.Errorf("Cardano requires 32-byte Ed25519 public keys")
	}

	// Hash both keys using Blake2b-224
	paymentHash := blake2b224(paymentKey)
	stakeHash := blake2b224(stakeKey)

	// Build address bytes
	var header byte
	if c.testnet {
		header = (CardanoBaseAddress << 4) | CardanoTestnet
	} else {
		header = (CardanoBaseAddress << 4) | CardanoMainnet
	}

	addressBytes := make([]byte, 1+CardanoKeyHashSize*2)
	addressBytes[0] = header
	copy(addressBytes[1:], paymentHash)
	copy(addressBytes[1+CardanoKeyHashSize:], stakeHash)

	// Encode with Bech32
	hrp := CardanoMainnetHRP
	if c.testnet {
		hrp = CardanoTestnetHRP
	}

	return Bech32Encode(hrp, addressBytes, Bech32Standard)
}

// GenerateRewardAddress creates a reward/stake address
func (c *CardanoAddress) GenerateRewardAddress(stakeKey []byte) (string, error) {
	if len(stakeKey) != 32 {
		return "", fmt.Errorf("Cardano requires 32-byte Ed25519 public key")
	}

	// Hash the stake key using Blake2b-224
	stakeHash := blake2b224(stakeKey)

	// Build address bytes
	var header byte
	if c.testnet {
		header = (CardanoRewardAddress << 4) | CardanoTestnet
	} else {
		header = (CardanoRewardAddress << 4) | CardanoMainnet
	}

	addressBytes := make([]byte, 1+CardanoKeyHashSize)
	addressBytes[0] = header
	copy(addressBytes[1:], stakeHash)

	// Encode with Bech32
	hrp := CardanoMainnetStakeHRP
	if c.testnet {
		hrp = CardanoTestnetStakeHRP
	}

	return Bech32Encode(hrp, addressBytes, Bech32Standard)
}

// Validate checks if a Cardano address is valid
func (c *CardanoAddress) Validate(address string) bool {
	hrp, data, _, err := Bech32Decode(address)
	if err != nil {
		return false
	}

	// Check HRP
	validHRPs := []string{
		CardanoMainnetHRP, CardanoTestnetHRP,
		CardanoMainnetStakeHRP, CardanoTestnetStakeHRP,
	}

	hrpValid := false
	for _, valid := range validHRPs {
		if hrp == valid {
			hrpValid = true
			break
		}
	}
	if !hrpValid {
		return false
	}

	// Check minimum length
	if len(data) < 1+CardanoKeyHashSize {
		return false
	}

	// Extract address type from header
	header := data[0]
	addrType := (header >> 4) & 0x0F
	network := header & 0x0F

	// Validate network tag
	if network != CardanoMainnet && network != CardanoTestnet {
		return false
	}

	// Validate address type and length
	switch addrType {
	case CardanoBaseAddress, CardanoScriptAddress, CardanoBaseScriptAddress, CardanoScriptScriptAddr:
		// Base addresses have payment hash + stake hash
		if len(data) != 1+CardanoKeyHashSize*2 {
			return false
		}
	case CardanoEnterpriseAddress, CardanoEnterpriseScript, CardanoRewardAddress, CardanoRewardScript:
		// Enterprise and reward addresses have single hash
		if len(data) != 1+CardanoKeyHashSize {
			return false
		}
	case CardanoPointerAddress, CardanoScriptPointer:
		// Pointer addresses have variable length (payment hash + pointer)
		if len(data) < 1+CardanoKeyHashSize+1 {
			return false
		}
	default:
		return false
	}

	return true
}

// DecodeAddress decodes a Cardano address
func (c *CardanoAddress) DecodeAddress(address string) (*AddressInfo, error) {
	if !c.Validate(address) {
		return nil, ErrInvalidAddress
	}

	hrp, data, _, err := Bech32Decode(address)
	if err != nil {
		return nil, err
	}

	header := data[0]
	addrType := (header >> 4) & 0x0F
	network := header & 0x0F

	info := &AddressInfo{
		Address: address,
		ChainID: ChainCardano,
		Type:    AddressTypeBech32,
	}

	// Extract payment key hash for base/enterprise addresses
	if addrType <= CardanoEnterpriseScript && len(data) > CardanoKeyHashSize {
		info.PublicKey = data[1 : 1+CardanoKeyHashSize]
	}

	// Add network info
	if network == CardanoTestnet {
		info.Type = AddressTypeBech32 // Could add testnet indicator
	}

	// Add HRP info
	_ = hrp // hrp is validated but not stored in AddressInfo currently

	return info, nil
}

// GetAddressType returns the type of address
func (c *CardanoAddress) GetAddressType(address string) (string, error) {
	if !c.Validate(address) {
		return "", ErrInvalidAddress
	}

	_, data, _, err := Bech32Decode(address)
	if err != nil {
		return "", err
	}

	header := data[0]
	addrType := (header >> 4) & 0x0F

	switch addrType {
	case CardanoBaseAddress:
		return "base (key/key)", nil
	case CardanoScriptAddress:
		return "base (script/key)", nil
	case CardanoBaseScriptAddress:
		return "base (key/script)", nil
	case CardanoScriptScriptAddr:
		return "base (script/script)", nil
	case CardanoPointerAddress:
		return "pointer (key)", nil
	case CardanoScriptPointer:
		return "pointer (script)", nil
	case CardanoEnterpriseAddress:
		return "enterprise (key)", nil
	case CardanoEnterpriseScript:
		return "enterprise (script)", nil
	case CardanoRewardAddress:
		return "reward (key)", nil
	case CardanoRewardScript:
		return "reward (script)", nil
	default:
		return "unknown", nil
	}
}

// blake2b224 computes Blake2b-224 hash (28 bytes)
func blake2b224(data []byte) []byte {
	h, err := blake2b.New(28, nil)
	if err != nil {
		// Fallback to SHA256 truncated (should never happen)
		hash := sha256.Sum256(data)
		return hash[:28]
	}
	h.Write(data)
	return h.Sum(nil)
}
