package bip44

import (
	"github.com/study/crypto-accounts/pkgs/bip32"
	"github.com/study/crypto-accounts/pkgs/bip39"
)

// Wallet represents a BIP-44 HD wallet.
type Wallet struct {
	masterKey *bip32.ExtendedKey
	mnemonic  string
}

// NewWalletFromSeed creates a new wallet from a seed.
func NewWalletFromSeed(seed []byte) (*Wallet, error) {
	master, err := bip32.NewMasterKey(seed)
	if err != nil {
		return nil, err
	}

	return &Wallet{
		masterKey: master,
	}, nil
}

// NewWalletFromMnemonic creates a new wallet from a mnemonic phrase.
func NewWalletFromMnemonic(mnemonic, passphrase string) (*Wallet, error) {
	if !bip39.ValidateMnemonic(mnemonic) {
		return nil, bip39.ErrInvalidMnemonic
	}

	seed := bip39.NewSeed(mnemonic, passphrase)
	wallet, err := NewWalletFromSeed(seed)
	if err != nil {
		return nil, err
	}
	wallet.mnemonic = mnemonic

	return wallet, nil
}

// GenerateWallet generates a new wallet with a random mnemonic.
func GenerateWallet(entropyBits int, passphrase string) (*Wallet, error) {
	mnemonic, seed, err := bip39.GenerateMnemonicAndSeed(entropyBits, passphrase)
	if err != nil {
		return nil, err
	}

	wallet, err := NewWalletFromSeed(seed)
	if err != nil {
		return nil, err
	}
	wallet.mnemonic = mnemonic

	return wallet, nil
}

// MasterKey returns the master extended key.
func (w *Wallet) MasterKey() *bip32.ExtendedKey {
	return w.masterKey
}

// Mnemonic returns the mnemonic phrase (if available).
func (w *Wallet) Mnemonic() string {
	return w.mnemonic
}

// DeriveAccount derives a BIP-44 account for a coin type.
// Path: m/44'/coinType'/account'
func (w *Wallet) DeriveAccount(coinType CoinType, accountIndex uint32) (*Account, error) {
	path := NewPath(coinType, accountIndex, 0, 0).AccountPath()
	accountKey, err := w.masterKey.DeriveFromPathString(path)
	if err != nil {
		return nil, err
	}

	return NewAccount(coinType, accountIndex, accountKey), nil
}

// DeriveKey derives a key at the specified BIP-44 path.
func (w *Wallet) DeriveKey(path *Path) (*bip32.ExtendedKey, error) {
	return w.masterKey.DeriveFromPathString(path.String())
}

// DeriveKeyFromString derives a key from a path string.
func (w *Wallet) DeriveKeyFromString(pathStr string) (*bip32.ExtendedKey, error) {
	return w.masterKey.DeriveFromPathString(pathStr)
}

// BitcoinAccount returns the Bitcoin account at the specified index.
func (w *Wallet) BitcoinAccount(accountIndex uint32) (*Account, error) {
	return w.DeriveAccount(CoinTypeBitcoin, accountIndex)
}

// EthereumAccount returns the Ethereum account at the specified index.
func (w *Wallet) EthereumAccount(accountIndex uint32) (*Account, error) {
	return w.DeriveAccount(CoinTypeEthereum, accountIndex)
}

// DeriveAddress is a convenience method to derive an address key directly.
func (w *Wallet) DeriveAddress(coinType CoinType, account, change, addressIndex uint32) (*bip32.ExtendedKey, error) {
	path := NewPath(coinType, account, change, addressIndex)
	return w.DeriveKey(path)
}

// GetAddressInfo returns full address information for the given path.
func (w *Wallet) GetAddressInfo(path *Path) (*AddressInfo, error) {
	key, err := w.DeriveKey(path)
	if err != nil {
		return nil, err
	}

	info := &AddressInfo{
		Path:      path,
		PublicKey: key.PublicKeyBytes(),
		ChainCode: key.ChainCode(),
	}

	if key.IsPrivate() {
		info.PrivateKey = key.PrivateKeyBytes()
	}

	return info, nil
}

// DeriveAddresses derives multiple addresses for a coin type.
func (w *Wallet) DeriveAddresses(coinType CoinType, account, change, startIndex, count uint32) ([]*AddressInfo, error) {
	acc, err := w.DeriveAccount(coinType, account)
	if err != nil {
		return nil, err
	}

	addresses := make([]*AddressInfo, count)
	for i := uint32(0); i < count; i++ {
		info, err := acc.GetAddressInfo(change, startIndex+i)
		if err != nil {
			return nil, err
		}
		addresses[i] = info
	}

	return addresses, nil
}
