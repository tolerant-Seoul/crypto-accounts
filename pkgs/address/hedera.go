package address

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// HederaAddress generates Hedera (HBAR) addresses/account IDs
// Hedera uses account IDs in format: shard.realm.account (e.g., 0.0.12345)
// It also supports alias addresses derived from public keys
type HederaAddress struct {
	shard uint64
	realm uint64
}

// NewHederaAddress creates a new Hedera address generator
func NewHederaAddress() *HederaAddress {
	return &HederaAddress{shard: 0, realm: 0}
}

// NewHederaAddressWithShardRealm creates a new Hedera address generator with custom shard/realm
func NewHederaAddressWithShardRealm(shard, realm uint64) *HederaAddress {
	return &HederaAddress{shard: shard, realm: realm}
}

// ChainID returns the chain identifier
func (h *HederaAddress) ChainID() ChainID {
	return ChainHedera
}

// Generate creates a Hedera alias address from a public key
// Public key can be 32 bytes (Ed25519) or 33 bytes (ECDSA secp256k1)
// Returns the hex-encoded public key as an alias
func (h *HederaAddress) Generate(publicKey []byte) (string, error) {
	if len(publicKey) != 32 && len(publicKey) != 33 {
		return "", fmt.Errorf("invalid public key length: expected 32 (Ed25519) or 33 (ECDSA), got %d", len(publicKey))
	}

	// Hedera supports public key aliases in hex format
	// Format: shard.realm.publicKeyHex
	pubKeyHex := hex.EncodeToString(publicKey)
	return fmt.Sprintf("%d.%d.%s", h.shard, h.realm, pubKeyHex), nil
}

// GenerateAccountID creates a standard account ID (not from public key)
// This is typically assigned by the network
func (h *HederaAddress) GenerateAccountID(accountNum uint64) string {
	return fmt.Sprintf("%d.%d.%d", h.shard, h.realm, accountNum)
}

// Validate checks if a Hedera account ID or alias is valid
func (h *HederaAddress) Validate(address string) bool {
	// Standard account ID format: shard.realm.account
	accountIDPattern := regexp.MustCompile(`^(\d+)\.(\d+)\.(\d+)$`)
	if accountIDPattern.MatchString(address) {
		return true
	}

	// Alias format: shard.realm.hexPublicKey
	aliasPattern := regexp.MustCompile(`^(\d+)\.(\d+)\.([0-9a-fA-F]+)$`)
	if matches := aliasPattern.FindStringSubmatch(address); matches != nil {
		hexPart := matches[3]
		// Public key should be 32 bytes (64 hex) for Ed25519 or 33 bytes (66 hex) for ECDSA
		if len(hexPart) == 64 || len(hexPart) == 66 {
			return true
		}
	}

	return false
}

// GetAddressType returns the type of Hedera address
func (h *HederaAddress) GetAddressType(address string) (string, error) {
	if !h.Validate(address) {
		return "", ErrInvalidAddress
	}

	parts := strings.Split(address, ".")
	if len(parts) != 3 {
		return "", ErrInvalidAddress
	}

	// Check if it's a numeric account ID or an alias
	if _, err := strconv.ParseUint(parts[2], 10, 64); err == nil {
		return "Account ID", nil
	}

	// It's an alias
	if len(parts[2]) == 64 {
		return "Ed25519 Alias", nil
	}
	if len(parts[2]) == 66 {
		return "ECDSA Alias", nil
	}

	return "Unknown Alias", nil
}

// DecodeAddress decodes a Hedera address
func (h *HederaAddress) DecodeAddress(address string) (*AddressInfo, error) {
	if !h.Validate(address) {
		return nil, ErrInvalidAddress
	}

	parts := strings.Split(address, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidAddress
	}

	var publicKey []byte

	// Check if it's an alias (hex public key)
	if len(parts[2]) == 64 || len(parts[2]) == 66 {
		var err error
		publicKey, err = hex.DecodeString(parts[2])
		if err != nil {
			return nil, err
		}
	}

	return &AddressInfo{
		Address:   address,
		PublicKey: publicKey, // May be nil for account IDs
		ChainID:   ChainHedera,
		Type:      AddressTypeBase58, // Using as placeholder
	}, nil
}

// ParseAccountID parses an account ID into its components
func (h *HederaAddress) ParseAccountID(address string) (shard, realm, account uint64, err error) {
	parts := strings.Split(address, ".")
	if len(parts) != 3 {
		return 0, 0, 0, fmt.Errorf("invalid account ID format")
	}

	shard, err = strconv.ParseUint(parts[0], 10, 64)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("invalid shard: %v", err)
	}

	realm, err = strconv.ParseUint(parts[1], 10, 64)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("invalid realm: %v", err)
	}

	account, err = strconv.ParseUint(parts[2], 10, 64)
	if err != nil {
		// Might be an alias, not a numeric account
		return shard, realm, 0, nil
	}

	return shard, realm, account, nil
}
