package bip44

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/study/crypto-accounts/pkgs/bip32"
)

const (
	// Purpose is the BIP-44 purpose constant (44').
	Purpose = 44

	// ExternalChain is used for receiving addresses.
	ExternalChain = 0

	// InternalChain is used for change addresses.
	InternalChain = 1
)

var (
	// ErrInvalidPath is returned when a path is invalid.
	ErrInvalidPath = errors.New("invalid BIP-44 path")

	// ErrInvalidPurpose is returned when purpose is not 44'.
	ErrInvalidPurpose = errors.New("invalid purpose: must be 44'")

	// ErrInvalidChange is returned when change value is not 0 or 1.
	ErrInvalidChange = errors.New("invalid change: must be 0 or 1")
)

// Path represents a BIP-44 derivation path.
type Path struct {
	Purpose      uint32
	CoinType     CoinType
	Account      uint32
	Change       uint32
	AddressIndex uint32
}

// NewPath creates a new BIP-44 path with default values.
func NewPath(coinType CoinType, account, change, addressIndex uint32) *Path {
	return &Path{
		Purpose:      Purpose,
		CoinType:     coinType,
		Account:      account,
		Change:       change,
		AddressIndex: addressIndex,
	}
}

// DefaultPath returns the default BIP-44 path for a coin type.
// Default: m/44'/coinType'/0'/0/0
func DefaultPath(coinType CoinType) *Path {
	return NewPath(coinType, 0, ExternalChain, 0)
}

// BitcoinPath returns the BIP-44 path for Bitcoin.
// m/44'/0'/account'/change/addressIndex
func BitcoinPath(account, change, addressIndex uint32) *Path {
	return NewPath(CoinTypeBitcoin, account, change, addressIndex)
}

// EthereumPath returns the BIP-44 path for Ethereum.
// m/44'/60'/account'/change/addressIndex
func EthereumPath(account, change, addressIndex uint32) *Path {
	return NewPath(CoinTypeEthereum, account, change, addressIndex)
}

// String returns the string representation of the path.
// Example: m/44'/0'/0'/0/0
func (p *Path) String() string {
	return fmt.Sprintf("m/%d'/%d'/%d'/%d/%d",
		p.Purpose,
		p.CoinType,
		p.Account,
		p.Change,
		p.AddressIndex,
	)
}

// ToBIP32Path converts the BIP-44 path to a BIP-32 derivation path.
func (p *Path) ToBIP32Path() bip32.DerivationPath {
	return bip32.DerivationPath{
		bip32.Hardened(p.Purpose),
		bip32.Hardened(uint32(p.CoinType)),
		bip32.Hardened(p.Account),
		p.Change,
		p.AddressIndex,
	}
}

// AccountPath returns the account-level path (m/44'/coin'/account').
func (p *Path) AccountPath() string {
	return fmt.Sprintf("m/%d'/%d'/%d'", p.Purpose, p.CoinType, p.Account)
}

// WithAccount returns a new path with the specified account.
func (p *Path) WithAccount(account uint32) *Path {
	return &Path{
		Purpose:      p.Purpose,
		CoinType:     p.CoinType,
		Account:      account,
		Change:       p.Change,
		AddressIndex: p.AddressIndex,
	}
}

// WithChange returns a new path with the specified change value.
func (p *Path) WithChange(change uint32) *Path {
	return &Path{
		Purpose:      p.Purpose,
		CoinType:     p.CoinType,
		Account:      p.Account,
		Change:       change,
		AddressIndex: p.AddressIndex,
	}
}

// WithAddressIndex returns a new path with the specified address index.
func (p *Path) WithAddressIndex(index uint32) *Path {
	return &Path{
		Purpose:      p.Purpose,
		CoinType:     p.CoinType,
		Account:      p.Account,
		Change:       p.Change,
		AddressIndex: index,
	}
}

// Next returns the next address path (incremented address index).
func (p *Path) Next() *Path {
	return p.WithAddressIndex(p.AddressIndex + 1)
}

// ParsePath parses a BIP-44 path string.
// Expected format: m/44'/coinType'/account'/change/addressIndex
func ParsePath(path string) (*Path, error) {
	path = strings.TrimSpace(path)
	if !strings.HasPrefix(path, "m/") {
		return nil, ErrInvalidPath
	}

	parts := strings.Split(path[2:], "/")
	if len(parts) != 5 {
		return nil, ErrInvalidPath
	}

	// Parse purpose (must be 44')
	purpose, err := parseHardenedIndex(parts[0])
	if err != nil || purpose != Purpose {
		return nil, ErrInvalidPurpose
	}

	// Parse coin type (hardened)
	coinType, err := parseHardenedIndex(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid coin type: %w", err)
	}

	// Parse account (hardened)
	account, err := parseHardenedIndex(parts[2])
	if err != nil {
		return nil, fmt.Errorf("invalid account: %w", err)
	}

	// Parse change (not hardened)
	change, err := parseIndex(parts[3])
	if err != nil {
		return nil, fmt.Errorf("invalid change: %w", err)
	}
	if change > 1 {
		return nil, ErrInvalidChange
	}

	// Parse address index (not hardened)
	addressIndex, err := parseIndex(parts[4])
	if err != nil {
		return nil, fmt.Errorf("invalid address index: %w", err)
	}

	return &Path{
		Purpose:      purpose,
		CoinType:     CoinType(coinType),
		Account:      account,
		Change:       change,
		AddressIndex: addressIndex,
	}, nil
}

// parseHardenedIndex parses a hardened index (e.g., "44'" or "44h").
func parseHardenedIndex(s string) (uint32, error) {
	s = strings.TrimSpace(s)
	if !strings.HasSuffix(s, "'") && !strings.HasSuffix(s, "h") {
		return 0, fmt.Errorf("expected hardened index: %s", s)
	}
	s = strings.TrimSuffix(strings.TrimSuffix(s, "'"), "h")
	val, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, err
	}
	return uint32(val), nil
}

// parseIndex parses a non-hardened index.
func parseIndex(s string) (uint32, error) {
	s = strings.TrimSpace(s)
	// Non-hardened indices shouldn't have ' or h suffix
	if strings.HasSuffix(s, "'") || strings.HasSuffix(s, "h") {
		return 0, fmt.Errorf("unexpected hardened index: %s", s)
	}
	val, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, err
	}
	return uint32(val), nil
}
