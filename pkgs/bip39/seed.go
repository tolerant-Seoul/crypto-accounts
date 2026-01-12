package bip39

import (
	"crypto/sha512"

	"golang.org/x/crypto/pbkdf2"
)

const (
	// SeedSize is the size of the generated seed in bytes (512 bits).
	SeedSize = 64

	// PBKDF2Iterations is the number of iterations for PBKDF2.
	PBKDF2Iterations = 2048

	// SaltPrefix is the prefix used for the PBKDF2 salt.
	SaltPrefix = "mnemonic"
)

// NewSeed generates a 512-bit seed from a mnemonic phrase.
// The passphrase is optional and can be empty.
func NewSeed(mnemonic string, passphrase string) []byte {
	salt := SaltPrefix + passphrase
	return pbkdf2.Key([]byte(mnemonic), []byte(salt), PBKDF2Iterations, SeedSize, sha512.New)
}

// NewSeedFromEntropy generates entropy, creates a mnemonic, and derives a seed.
// This is a convenience function that combines entropy generation, mnemonic creation, and seed derivation.
func NewSeedFromEntropy(entropy []byte, passphrase string) (string, []byte, error) {
	mnemonic, err := NewMnemonic(entropy)
	if err != nil {
		return "", nil, err
	}

	seed := NewSeed(mnemonic, passphrase)
	return mnemonic, seed, nil
}

// GenerateMnemonicAndSeed generates a new random mnemonic and derives its seed.
// bits specifies the entropy size (128, 160, 192, 224, or 256).
// passphrase is optional and can be empty.
func GenerateMnemonicAndSeed(bits int, passphrase string) (string, []byte, error) {
	entropy, err := GenerateEntropy(bits)
	if err != nil {
		return "", nil, err
	}

	return NewSeedFromEntropy(entropy, passphrase)
}
