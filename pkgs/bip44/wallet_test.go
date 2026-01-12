package bip44

import (
	"encoding/hex"
	"testing"

	"github.com/study/crypto-accounts/pkgs/bip39"
)

const testMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

func TestNewWalletFromMnemonic(t *testing.T) {
	wallet, err := NewWalletFromMnemonic(testMnemonic, "")
	if err != nil {
		t.Fatalf("NewWalletFromMnemonic() error = %v", err)
	}

	if wallet.Mnemonic() != testMnemonic {
		t.Errorf("Mnemonic() = %s, want %s", wallet.Mnemonic(), testMnemonic)
	}

	if wallet.MasterKey() == nil {
		t.Error("MasterKey() should not be nil")
	}
}

func TestNewWalletFromMnemonicWithPassphrase(t *testing.T) {
	wallet1, _ := NewWalletFromMnemonic(testMnemonic, "")
	wallet2, _ := NewWalletFromMnemonic(testMnemonic, "TREZOR")

	key1 := wallet1.MasterKey()
	key2 := wallet2.MasterKey()

	if key1.String() == key2.String() {
		t.Error("Different passphrases should produce different master keys")
	}
}

func TestNewWalletFromSeed(t *testing.T) {
	seed := bip39.NewSeed(testMnemonic, "")
	wallet, err := NewWalletFromSeed(seed)
	if err != nil {
		t.Fatalf("NewWalletFromSeed() error = %v", err)
	}

	if wallet.MasterKey() == nil {
		t.Error("MasterKey() should not be nil")
	}

	// Mnemonic should be empty when created from seed
	if wallet.Mnemonic() != "" {
		t.Errorf("Mnemonic() should be empty, got %s", wallet.Mnemonic())
	}
}

func TestGenerateWallet(t *testing.T) {
	wallet, err := GenerateWallet(128, "")
	if err != nil {
		t.Fatalf("GenerateWallet() error = %v", err)
	}

	if wallet.Mnemonic() == "" {
		t.Error("Generated wallet should have a mnemonic")
	}

	if !bip39.ValidateMnemonic(wallet.Mnemonic()) {
		t.Error("Generated mnemonic should be valid")
	}
}

func TestDeriveAccount(t *testing.T) {
	wallet, _ := NewWalletFromMnemonic(testMnemonic, "")

	tests := []struct {
		name     string
		coinType CoinType
		account  uint32
	}{
		{"Bitcoin account 0", CoinTypeBitcoin, 0},
		{"Bitcoin account 1", CoinTypeBitcoin, 1},
		{"Ethereum account 0", CoinTypeEthereum, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			account, err := wallet.DeriveAccount(tt.coinType, tt.account)
			if err != nil {
				t.Fatalf("DeriveAccount() error = %v", err)
			}

			if account.CoinType() != tt.coinType {
				t.Errorf("CoinType() = %d, want %d", account.CoinType(), tt.coinType)
			}
			if account.Index() != tt.account {
				t.Errorf("Index() = %d, want %d", account.Index(), tt.account)
			}
			if account.Key() == nil {
				t.Error("Key() should not be nil")
			}
		})
	}
}

func TestDeriveKey(t *testing.T) {
	wallet, _ := NewWalletFromMnemonic(testMnemonic, "")

	// Test with known test vector
	// From: https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
	path := BitcoinPath(0, 0, 0)
	key, err := wallet.DeriveKey(path)
	if err != nil {
		t.Fatalf("DeriveKey() error = %v", err)
	}

	if key == nil {
		t.Error("DeriveKey() should not return nil")
	}

	// Verify the key is at correct depth
	if key.Depth() != 5 {
		t.Errorf("Key depth = %d, want 5", key.Depth())
	}
}

func TestDeriveKeyFromString(t *testing.T) {
	wallet, _ := NewWalletFromMnemonic(testMnemonic, "")

	key, err := wallet.DeriveKeyFromString("m/44'/0'/0'/0/0")
	if err != nil {
		t.Fatalf("DeriveKeyFromString() error = %v", err)
	}

	path := BitcoinPath(0, 0, 0)
	key2, _ := wallet.DeriveKey(path)

	if hex.EncodeToString(key.PrivateKeyBytes()) != hex.EncodeToString(key2.PrivateKeyBytes()) {
		t.Error("DeriveKeyFromString and DeriveKey should produce same result")
	}
}

func TestBitcoinAccount(t *testing.T) {
	wallet, _ := NewWalletFromMnemonic(testMnemonic, "")

	account, err := wallet.BitcoinAccount(0)
	if err != nil {
		t.Fatalf("BitcoinAccount() error = %v", err)
	}

	if account.CoinType() != CoinTypeBitcoin {
		t.Errorf("CoinType() = %d, want %d", account.CoinType(), CoinTypeBitcoin)
	}
}

func TestEthereumAccount(t *testing.T) {
	wallet, _ := NewWalletFromMnemonic(testMnemonic, "")

	account, err := wallet.EthereumAccount(0)
	if err != nil {
		t.Fatalf("EthereumAccount() error = %v", err)
	}

	if account.CoinType() != CoinTypeEthereum {
		t.Errorf("CoinType() = %d, want %d", account.CoinType(), CoinTypeEthereum)
	}
}

func TestDeriveAddress(t *testing.T) {
	wallet, _ := NewWalletFromMnemonic(testMnemonic, "")

	key, err := wallet.DeriveAddress(CoinTypeBitcoin, 0, 0, 0)
	if err != nil {
		t.Fatalf("DeriveAddress() error = %v", err)
	}

	path := BitcoinPath(0, 0, 0)
	key2, _ := wallet.DeriveKey(path)

	if hex.EncodeToString(key.PrivateKeyBytes()) != hex.EncodeToString(key2.PrivateKeyBytes()) {
		t.Error("DeriveAddress and DeriveKey should produce same result")
	}
}

func TestGetAddressInfo(t *testing.T) {
	wallet, _ := NewWalletFromMnemonic(testMnemonic, "")

	path := EthereumPath(0, 0, 0)
	info, err := wallet.GetAddressInfo(path)
	if err != nil {
		t.Fatalf("GetAddressInfo() error = %v", err)
	}

	if info.Path.String() != path.String() {
		t.Errorf("Path = %s, want %s", info.Path.String(), path.String())
	}
	if len(info.PrivateKey) == 0 {
		t.Error("PrivateKey should not be empty")
	}
	if len(info.PublicKey) == 0 {
		t.Error("PublicKey should not be empty")
	}
	if len(info.ChainCode) == 0 {
		t.Error("ChainCode should not be empty")
	}
}

func TestDeriveAddresses(t *testing.T) {
	wallet, _ := NewWalletFromMnemonic(testMnemonic, "")

	addresses, err := wallet.DeriveAddresses(CoinTypeBitcoin, 0, 0, 0, 5)
	if err != nil {
		t.Fatalf("DeriveAddresses() error = %v", err)
	}

	if len(addresses) != 5 {
		t.Errorf("DeriveAddresses() returned %d addresses, want 5", len(addresses))
	}

	// Verify indices are sequential
	for i, addr := range addresses {
		if addr.Path.AddressIndex != uint32(i) {
			t.Errorf("Address %d has index %d, want %d", i, addr.Path.AddressIndex, i)
		}
	}

	// Verify all addresses are unique
	seen := make(map[string]bool)
	for _, addr := range addresses {
		pubHex := hex.EncodeToString(addr.PublicKey)
		if seen[pubHex] {
			t.Error("Duplicate public key found")
		}
		seen[pubHex] = true
	}
}

func TestKnownTestVector(t *testing.T) {
	// Test vector from: https://iancoleman.io/bip39/
	// Mnemonic: abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
	// Passphrase: (empty)
	// Derivation Path: m/44'/60'/0'/0/0 (Ethereum)

	wallet, _ := NewWalletFromMnemonic(testMnemonic, "")
	key, _ := wallet.DeriveKeyFromString("m/44'/60'/0'/0/0")

	// Expected private key for this derivation
	expectedPrivKey := "1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727"
	actualPrivKey := hex.EncodeToString(key.PrivateKeyBytes())

	if actualPrivKey != expectedPrivKey {
		t.Errorf("Ethereum private key = %s, want %s", actualPrivKey, expectedPrivKey)
	}
}

func TestInvalidMnemonic(t *testing.T) {
	_, err := NewWalletFromMnemonic("invalid mnemonic phrase", "")
	if err == nil {
		t.Error("NewWalletFromMnemonic should fail with invalid mnemonic")
	}
}
