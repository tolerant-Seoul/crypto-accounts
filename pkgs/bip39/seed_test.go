package bip39

import (
	"encoding/hex"
	"testing"
)

func TestNewSeed(t *testing.T) {
	// Official BIP-39 test vectors
	// https://github.com/trezor/python-mnemonic/blob/master/vectors.json
	// Note: All official test vectors use "TREZOR" as the passphrase
	tests := []struct {
		name       string
		mnemonic   string
		passphrase string
		expected   string // hex
	}{
		{
			name:       "12 words - abandon...about",
			mnemonic:   "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
			passphrase: "TREZOR",
			expected:   "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
		},
		{
			name:       "12 words - legal winner",
			mnemonic:   "legal winner thank year wave sausage worth useful legal winner thank yellow",
			passphrase: "TREZOR",
			expected:   "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607",
		},
		{
			name:       "12 words - letter advice",
			mnemonic:   "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
			passphrase: "TREZOR",
			expected:   "d71de856f81a8acc65e6fc851a38d4d7ec216fd0796d0a6827a3ad6ed5511a30fa280f12eb2e47ed2ac03b5c462a0358d18d69fe4f985ec81778c1b370b652a8",
		},
		{
			name:       "12 words - zoo wrong",
			mnemonic:   "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
			passphrase: "TREZOR",
			expected:   "ac27495480225222079d7be181583751e86f571027b0497b5b5d11218e0a8a13332572917f0f8e5a589620c6f15b11c61dee327651a14c34e18231052e48c069",
		},
		{
			name:       "24 words - abandon...art",
			mnemonic:   "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
			passphrase: "TREZOR",
			expected:   "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8",
		},
		{
			name:       "24 words - zoo vote",
			mnemonic:   "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
			passphrase: "TREZOR",
			expected:   "dd48c104698c30cfe2b6142103248622fb7bb0ff692eebb00089b32d22484e1613912f0a5b694407be899ffd31ed3992c456cdf60f5d4564b8ba3f05a69890ad",
		},
		{
			name:       "empty passphrase",
			mnemonic:   "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
			passphrase: "",
			expected:   "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			seed := NewSeed(tt.mnemonic, tt.passphrase)
			got := hex.EncodeToString(seed)
			if got != tt.expected {
				t.Errorf("NewSeed() = %s, want %s", got, tt.expected)
			}
		})
	}
}

func TestNewSeedFromEntropy(t *testing.T) {
	entropy, _ := hex.DecodeString("00000000000000000000000000000000")
	expectedMnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	expectedSeed := "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"

	mnemonic, seed, err := NewSeedFromEntropy(entropy, "")
	if err != nil {
		t.Fatalf("NewSeedFromEntropy() error = %v", err)
	}

	if mnemonic != expectedMnemonic {
		t.Errorf("NewSeedFromEntropy() mnemonic = %q, want %q", mnemonic, expectedMnemonic)
	}

	if hex.EncodeToString(seed) != expectedSeed {
		t.Errorf("NewSeedFromEntropy() seed = %x, want %s", seed, expectedSeed)
	}
}

func TestGenerateMnemonicAndSeed(t *testing.T) {
	for _, bits := range ValidEntropyBits {
		mnemonic, seed, err := GenerateMnemonicAndSeed(bits, "")
		if err != nil {
			t.Errorf("GenerateMnemonicAndSeed(%d) error = %v", bits, err)
			continue
		}

		if !ValidateMnemonic(mnemonic) {
			t.Errorf("GenerateMnemonicAndSeed(%d) generated invalid mnemonic", bits)
		}

		if len(seed) != SeedSize {
			t.Errorf("GenerateMnemonicAndSeed(%d) seed length = %d, want %d", bits, len(seed), SeedSize)
		}

		// Verify word count
		expectedWords := EntropyToWordCount[bits]
		words := len(splitWords(mnemonic))
		if words != expectedWords {
			t.Errorf("GenerateMnemonicAndSeed(%d) word count = %d, want %d", bits, words, expectedWords)
		}
	}
}

func splitWords(s string) []string {
	var words []string
	word := ""
	for _, r := range s {
		if r == ' ' {
			if word != "" {
				words = append(words, word)
				word = ""
			}
		} else {
			word += string(r)
		}
	}
	if word != "" {
		words = append(words, word)
	}
	return words
}

func TestSeedSize(t *testing.T) {
	if SeedSize != 64 {
		t.Errorf("SeedSize = %d, want 64", SeedSize)
	}
}

func TestPBKDF2Iterations(t *testing.T) {
	if PBKDF2Iterations != 2048 {
		t.Errorf("PBKDF2Iterations = %d, want 2048", PBKDF2Iterations)
	}
}
