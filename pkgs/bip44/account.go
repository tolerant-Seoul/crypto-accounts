package bip44

import (
	"github.com/study/crypto-accounts/pkgs/bip32"
)

// Account represents a BIP-44 account for a specific coin type.
type Account struct {
	coinType   CoinType
	index      uint32
	accountKey *bip32.ExtendedKey
}

// NewAccount creates a new account from an account-level extended key.
func NewAccount(coinType CoinType, index uint32, accountKey *bip32.ExtendedKey) *Account {
	return &Account{
		coinType:   coinType,
		index:      index,
		accountKey: accountKey,
	}
}

// CoinType returns the coin type of this account.
func (a *Account) CoinType() CoinType {
	return a.coinType
}

// Index returns the account index.
func (a *Account) Index() uint32 {
	return a.index
}

// Key returns the account-level extended key.
func (a *Account) Key() *bip32.ExtendedKey {
	return a.accountKey
}

// PublicKey returns the account-level extended public key.
func (a *Account) PublicKey() (*bip32.ExtendedKey, error) {
	pub, err := a.accountKey.Neuter()
	if err != nil {
		return nil, err
	}
	return pub.(*bip32.ExtendedKey), nil
}

// DeriveAddress derives an address key at the specified change and index.
func (a *Account) DeriveAddress(change, index uint32) (*bip32.ExtendedKey, error) {
	// Derive change level: account / change
	changeKey, err := a.accountKey.Child(change)
	if err != nil {
		return nil, err
	}

	// Derive address level: account / change / index
	addressKey, err := changeKey.Child(index)
	if err != nil {
		return nil, err
	}

	return addressKey.(*bip32.ExtendedKey), nil
}

// DeriveExternalAddress derives an external (receiving) address.
func (a *Account) DeriveExternalAddress(index uint32) (*bip32.ExtendedKey, error) {
	return a.DeriveAddress(ExternalChain, index)
}

// DeriveInternalAddress derives an internal (change) address.
func (a *Account) DeriveInternalAddress(index uint32) (*bip32.ExtendedKey, error) {
	return a.DeriveAddress(InternalChain, index)
}

// DeriveAddresses derives multiple consecutive addresses.
func (a *Account) DeriveAddresses(change, startIndex, count uint32) ([]*bip32.ExtendedKey, error) {
	// Derive change level once
	changeKey, err := a.accountKey.Child(change)
	if err != nil {
		return nil, err
	}

	addresses := make([]*bip32.ExtendedKey, count)
	for i := uint32(0); i < count; i++ {
		addr, err := changeKey.Child(startIndex + i)
		if err != nil {
			return nil, err
		}
		addresses[i] = addr.(*bip32.ExtendedKey)
	}

	return addresses, nil
}

// Path returns the BIP-44 path for an address in this account.
func (a *Account) Path(change, index uint32) *Path {
	return NewPath(a.coinType, a.index, change, index)
}

// ExternalPath returns the BIP-44 path for an external address.
func (a *Account) ExternalPath(index uint32) *Path {
	return a.Path(ExternalChain, index)
}

// InternalPath returns the BIP-44 path for an internal (change) address.
func (a *Account) InternalPath(index uint32) *Path {
	return a.Path(InternalChain, index)
}

// AddressInfo contains information about a derived address.
type AddressInfo struct {
	Path       *Path
	PrivateKey []byte
	PublicKey  []byte
	ChainCode  []byte
}

// GetAddressInfo derives an address and returns its full information.
func (a *Account) GetAddressInfo(change, index uint32) (*AddressInfo, error) {
	key, err := a.DeriveAddress(change, index)
	if err != nil {
		return nil, err
	}

	info := &AddressInfo{
		Path:      a.Path(change, index),
		PublicKey: key.PublicKeyBytes(),
		ChainCode: key.ChainCode(),
	}

	if key.IsPrivate() {
		info.PrivateKey = key.PrivateKeyBytes()
	}

	return info, nil
}
