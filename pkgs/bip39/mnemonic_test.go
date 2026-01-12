package bip39

import (
	"encoding/hex"
	"testing"
)

func TestGenerateEntropy(t *testing.T) {
	tests := []struct {
		bits    int
		wantErr bool
	}{
		{128, false},
		{160, false},
		{192, false},
		{224, false},
		{256, false},
		{64, true},   // too small
		{512, true},  // too large
		{129, true},  // invalid
	}

	for _, tt := range tests {
		entropy, err := GenerateEntropy(tt.bits)
		if (err != nil) != tt.wantErr {
			t.Errorf("GenerateEntropy(%d) error = %v, wantErr %v", tt.bits, err, tt.wantErr)
			continue
		}
		if !tt.wantErr && len(entropy) != tt.bits/8 {
			t.Errorf("GenerateEntropy(%d) length = %d, want %d", tt.bits, len(entropy), tt.bits/8)
		}
	}
}

func TestNewMnemonic(t *testing.T) {
	tests := []struct {
		name     string
		entropy  string // hex
		expected string
	}{
		{
			name:     "128-bit entropy",
			entropy:  "00000000000000000000000000000000",
			expected: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
		},
		{
			name:     "256-bit entropy all zeros",
			entropy:  "0000000000000000000000000000000000000000000000000000000000000000",
			expected: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
		},
		{
			name:     "128-bit entropy all ones",
			entropy:  "ffffffffffffffffffffffffffffffff",
			expected: "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
		},
		{
			name:     "256-bit entropy all ones",
			entropy:  "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			expected: "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
		},
		{
			name:     "test vector 1",
			entropy:  "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
			expected: "legal winner thank year wave sausage worth useful legal winner thank yellow",
		},
		{
			name:     "test vector 2",
			entropy:  "80808080808080808080808080808080",
			expected: "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entropy, _ := hex.DecodeString(tt.entropy)
			mnemonic, err := NewMnemonic(entropy)
			if err != nil {
				t.Fatalf("NewMnemonic() error = %v", err)
			}
			if mnemonic != tt.expected {
				t.Errorf("NewMnemonic() = %q, want %q", mnemonic, tt.expected)
			}
		})
	}
}

func TestMnemonicToEntropy(t *testing.T) {
	tests := []struct {
		name     string
		mnemonic string
		expected string // hex
		wantErr  bool
	}{
		{
			name:     "valid 12 words",
			mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
			expected: "00000000000000000000000000000000",
			wantErr:  false,
		},
		{
			name:     "valid 24 words",
			mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
			expected: "0000000000000000000000000000000000000000000000000000000000000000",
			wantErr:  false,
		},
		{
			name:     "invalid word count",
			mnemonic: "abandon abandon abandon",
			wantErr:  true,
		},
		{
			name:     "invalid word",
			mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon invalid",
			wantErr:  true,
		},
		{
			name:     "invalid checksum",
			mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entropy, err := MnemonicToEntropy(tt.mnemonic)
			if (err != nil) != tt.wantErr {
				t.Errorf("MnemonicToEntropy() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				got := hex.EncodeToString(entropy)
				if got != tt.expected {
					t.Errorf("MnemonicToEntropy() = %s, want %s", got, tt.expected)
				}
			}
		})
	}
}

func TestValidateMnemonic(t *testing.T) {
	tests := []struct {
		name     string
		mnemonic string
		valid    bool
	}{
		{
			name:     "valid 12 words",
			mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
			valid:    true,
		},
		{
			name:     "valid 24 words",
			mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
			valid:    true,
		},
		{
			name:     "invalid word count",
			mnemonic: "abandon abandon abandon",
			valid:    false,
		},
		{
			name:     "invalid word",
			mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon invalid",
			valid:    false,
		},
		{
			name:     "invalid checksum",
			mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon",
			valid:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ValidateMnemonic(tt.mnemonic); got != tt.valid {
				t.Errorf("ValidateMnemonic() = %v, want %v", got, tt.valid)
			}
		})
	}
}

func TestMnemonicRoundTrip(t *testing.T) {
	// Test round-trip for all valid entropy sizes
	for _, bits := range ValidEntropyBits {
		t.Run(string(rune(bits)), func(t *testing.T) {
			entropy, err := GenerateEntropy(bits)
			if err != nil {
				t.Fatalf("GenerateEntropy(%d) error = %v", bits, err)
			}

			mnemonic, err := NewMnemonic(entropy)
			if err != nil {
				t.Fatalf("NewMnemonic() error = %v", err)
			}

			recovered, err := MnemonicToEntropy(mnemonic)
			if err != nil {
				t.Fatalf("MnemonicToEntropy() error = %v", err)
			}

			if hex.EncodeToString(recovered) != hex.EncodeToString(entropy) {
				t.Errorf("Round-trip failed: original = %x, recovered = %x", entropy, recovered)
			}
		})
	}
}
