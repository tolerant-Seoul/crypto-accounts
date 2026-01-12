package bip44

import (
	"testing"
)

func TestNewPath(t *testing.T) {
	path := NewPath(CoinTypeEthereum, 0, ExternalChain, 5)

	if path.Purpose != Purpose {
		t.Errorf("Purpose = %d, want %d", path.Purpose, Purpose)
	}
	if path.CoinType != CoinTypeEthereum {
		t.Errorf("CoinType = %d, want %d", path.CoinType, CoinTypeEthereum)
	}
	if path.Account != 0 {
		t.Errorf("Account = %d, want 0", path.Account)
	}
	if path.Change != ExternalChain {
		t.Errorf("Change = %d, want %d", path.Change, ExternalChain)
	}
	if path.AddressIndex != 5 {
		t.Errorf("AddressIndex = %d, want 5", path.AddressIndex)
	}
}

func TestDefaultPath(t *testing.T) {
	tests := []struct {
		name     string
		coinType CoinType
		expected string
	}{
		{"Bitcoin", CoinTypeBitcoin, "m/44'/0'/0'/0/0"},
		{"Ethereum", CoinTypeEthereum, "m/44'/60'/0'/0/0"},
		{"Litecoin", CoinTypeLitecoin, "m/44'/2'/0'/0/0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := DefaultPath(tt.coinType)
			if path.String() != tt.expected {
				t.Errorf("DefaultPath(%v).String() = %s, want %s", tt.coinType, path.String(), tt.expected)
			}
		})
	}
}

func TestBitcoinPath(t *testing.T) {
	path := BitcoinPath(1, InternalChain, 10)
	expected := "m/44'/0'/1'/1/10"

	if path.String() != expected {
		t.Errorf("BitcoinPath(1, 1, 10).String() = %s, want %s", path.String(), expected)
	}
}

func TestEthereumPath(t *testing.T) {
	path := EthereumPath(2, ExternalChain, 5)
	expected := "m/44'/60'/2'/0/5"

	if path.String() != expected {
		t.Errorf("EthereumPath(2, 0, 5).String() = %s, want %s", path.String(), expected)
	}
}

func TestPathString(t *testing.T) {
	tests := []struct {
		name     string
		path     *Path
		expected string
	}{
		{
			name:     "Bitcoin first address",
			path:     NewPath(CoinTypeBitcoin, 0, 0, 0),
			expected: "m/44'/0'/0'/0/0",
		},
		{
			name:     "Ethereum account 1",
			path:     NewPath(CoinTypeEthereum, 1, 0, 0),
			expected: "m/44'/60'/1'/0/0",
		},
		{
			name:     "Bitcoin change address",
			path:     NewPath(CoinTypeBitcoin, 0, 1, 5),
			expected: "m/44'/0'/0'/1/5",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.path.String() != tt.expected {
				t.Errorf("String() = %s, want %s", tt.path.String(), tt.expected)
			}
		})
	}
}

func TestParsePath(t *testing.T) {
	tests := []struct {
		name         string
		pathStr      string
		wantCoinType CoinType
		wantAccount  uint32
		wantChange   uint32
		wantIndex    uint32
		wantErr      bool
	}{
		{
			name:         "Bitcoin default",
			pathStr:      "m/44'/0'/0'/0/0",
			wantCoinType: CoinTypeBitcoin,
			wantAccount:  0,
			wantChange:   0,
			wantIndex:    0,
			wantErr:      false,
		},
		{
			name:         "Ethereum account 1",
			pathStr:      "m/44'/60'/1'/0/5",
			wantCoinType: CoinTypeEthereum,
			wantAccount:  1,
			wantChange:   0,
			wantIndex:    5,
			wantErr:      false,
		},
		{
			name:         "Bitcoin change",
			pathStr:      "m/44'/0'/0'/1/10",
			wantCoinType: CoinTypeBitcoin,
			wantAccount:  0,
			wantChange:   1,
			wantIndex:    10,
			wantErr:      false,
		},
		{
			name:    "invalid purpose",
			pathStr: "m/49'/0'/0'/0/0",
			wantErr: true,
		},
		{
			name:    "missing m prefix",
			pathStr: "44'/0'/0'/0/0",
			wantErr: true,
		},
		{
			name:    "invalid change value",
			pathStr: "m/44'/0'/0'/2/0",
			wantErr: true,
		},
		{
			name:    "too few components",
			pathStr: "m/44'/0'/0'/0",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path, err := ParsePath(tt.pathStr)

			if (err != nil) != tt.wantErr {
				t.Errorf("ParsePath() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if path.CoinType != tt.wantCoinType {
					t.Errorf("CoinType = %d, want %d", path.CoinType, tt.wantCoinType)
				}
				if path.Account != tt.wantAccount {
					t.Errorf("Account = %d, want %d", path.Account, tt.wantAccount)
				}
				if path.Change != tt.wantChange {
					t.Errorf("Change = %d, want %d", path.Change, tt.wantChange)
				}
				if path.AddressIndex != tt.wantIndex {
					t.Errorf("AddressIndex = %d, want %d", path.AddressIndex, tt.wantIndex)
				}
			}
		})
	}
}

func TestPathWithMethods(t *testing.T) {
	path := DefaultPath(CoinTypeBitcoin)

	// Test WithAccount
	withAccount := path.WithAccount(5)
	if withAccount.Account != 5 {
		t.Errorf("WithAccount(5).Account = %d, want 5", withAccount.Account)
	}
	if path.Account != 0 {
		t.Error("Original path should not be modified")
	}

	// Test WithChange
	withChange := path.WithChange(InternalChain)
	if withChange.Change != InternalChain {
		t.Errorf("WithChange(1).Change = %d, want 1", withChange.Change)
	}

	// Test WithAddressIndex
	withIndex := path.WithAddressIndex(10)
	if withIndex.AddressIndex != 10 {
		t.Errorf("WithAddressIndex(10).AddressIndex = %d, want 10", withIndex.AddressIndex)
	}

	// Test Next
	next := path.Next()
	if next.AddressIndex != 1 {
		t.Errorf("Next().AddressIndex = %d, want 1", next.AddressIndex)
	}
}

func TestAccountPath(t *testing.T) {
	path := NewPath(CoinTypeEthereum, 2, 0, 5)
	expected := "m/44'/60'/2'"

	if path.AccountPath() != expected {
		t.Errorf("AccountPath() = %s, want %s", path.AccountPath(), expected)
	}
}

func TestToBIP32Path(t *testing.T) {
	path := NewPath(CoinTypeBitcoin, 0, 0, 0)
	bip32Path := path.ToBIP32Path()

	if len(bip32Path) != 5 {
		t.Errorf("ToBIP32Path() length = %d, want 5", len(bip32Path))
	}

	// Expected: [44+0x80000000, 0+0x80000000, 0+0x80000000, 0, 0]
	expected := []uint32{
		44 + 0x80000000,  // 44'
		0 + 0x80000000,   // 0'
		0 + 0x80000000,   // 0'
		0,                // 0
		0,                // 0
	}

	for i, exp := range expected {
		if bip32Path[i] != exp {
			t.Errorf("ToBIP32Path()[%d] = %d, want %d", i, bip32Path[i], exp)
		}
	}
}
