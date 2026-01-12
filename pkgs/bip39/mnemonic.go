package bip39

import (
	"crypto/rand"
	"crypto/sha256"
	"strings"
)

// ValidEntropyBits contains valid entropy sizes in bits.
var ValidEntropyBits = []int{128, 160, 192, 224, 256}

// EntropyToWordCount maps entropy bits to mnemonic word count.
var EntropyToWordCount = map[int]int{
	128: 12,
	160: 15,
	192: 18,
	224: 21,
	256: 24,
}

// GenerateEntropy generates random entropy of the specified bit length.
// Valid lengths are 128, 160, 192, 224, or 256 bits.
func GenerateEntropy(bits int) ([]byte, error) {
	if !isValidEntropyBits(bits) {
		return nil, ErrInvalidEntropyLength
	}

	entropy := make([]byte, bits/8)
	if _, err := rand.Read(entropy); err != nil {
		return nil, err
	}

	return entropy, nil
}

// NewMnemonic generates a mnemonic phrase from entropy.
func NewMnemonic(entropy []byte) (string, error) {
	return NewMnemonicWithWordList(entropy, DefaultWordList)
}

// NewMnemonicWithWordList generates a mnemonic phrase from entropy using a specific word list.
func NewMnemonicWithWordList(entropy []byte, wordList WordList) (string, error) {
	entropyBits := len(entropy) * 8
	if !isValidEntropyBits(entropyBits) {
		return "", ErrInvalidEntropyLength
	}

	// Calculate checksum
	hash := sha256.Sum256(entropy)
	checksumBits := entropyBits / 32

	// Combine entropy and checksum into bit array
	totalBits := entropyBits + checksumBits
	bits := make([]bool, totalBits)

	// Add entropy bits
	for i := 0; i < entropyBits; i++ {
		bits[i] = (entropy[i/8] & (1 << (7 - (i % 8)))) != 0
	}

	// Add checksum bits
	for i := 0; i < checksumBits; i++ {
		bits[entropyBits+i] = (hash[0] & (1 << (7 - i))) != 0
	}

	// Convert to word indices (11 bits per word)
	wordCount := totalBits / 11
	words := make([]string, wordCount)

	for i := 0; i < wordCount; i++ {
		index := 0
		for j := 0; j < 11; j++ {
			if bits[i*11+j] {
				index |= 1 << (10 - j)
			}
		}
		words[i] = wordList.WordAt(index)
	}

	return strings.Join(words, " "), nil
}

// MnemonicToEntropy converts a mnemonic phrase back to entropy.
func MnemonicToEntropy(mnemonic string) ([]byte, error) {
	return MnemonicToEntropyWithWordList(mnemonic, DefaultWordList)
}

// MnemonicToEntropyWithWordList converts a mnemonic phrase back to entropy using a specific word list.
func MnemonicToEntropyWithWordList(mnemonic string, wordList WordList) ([]byte, error) {
	words := strings.Fields(mnemonic)
	wordCount := len(words)

	// Validate word count
	if !isValidWordCount(wordCount) {
		return nil, ErrInvalidMnemonicLength
	}

	// Convert words to bit array
	totalBits := wordCount * 11
	bits := make([]bool, totalBits)

	for i, word := range words {
		index := wordList.WordIndex(word)
		if index == -1 {
			return nil, ErrInvalidMnemonic
		}

		for j := 0; j < 11; j++ {
			bits[i*11+j] = (index & (1 << (10 - j))) != 0
		}
	}

	// Calculate entropy and checksum sizes
	checksumBits := wordCount / 3
	entropyBits := totalBits - checksumBits

	// Extract entropy bytes
	entropy := make([]byte, entropyBits/8)
	for i := 0; i < entropyBits; i++ {
		if bits[i] {
			entropy[i/8] |= 1 << (7 - (i % 8))
		}
	}

	// Verify checksum
	hash := sha256.Sum256(entropy)
	for i := 0; i < checksumBits; i++ {
		expectedBit := (hash[0] & (1 << (7 - i))) != 0
		if bits[entropyBits+i] != expectedBit {
			return nil, ErrInvalidChecksum
		}
	}

	return entropy, nil
}

// ValidateMnemonic checks if a mnemonic phrase is valid.
func ValidateMnemonic(mnemonic string) bool {
	return ValidateMnemonicWithWordList(mnemonic, DefaultWordList)
}

// ValidateMnemonicWithWordList checks if a mnemonic phrase is valid using a specific word list.
func ValidateMnemonicWithWordList(mnemonic string, wordList WordList) bool {
	_, err := MnemonicToEntropyWithWordList(mnemonic, wordList)
	return err == nil
}

// isValidEntropyBits checks if entropy bit length is valid.
func isValidEntropyBits(bits int) bool {
	for _, valid := range ValidEntropyBits {
		if bits == valid {
			return true
		}
	}
	return false
}

// isValidWordCount checks if word count is valid.
func isValidWordCount(count int) bool {
	validCounts := []int{12, 15, 18, 21, 24}
	for _, valid := range validCounts {
		if count == valid {
			return true
		}
	}
	return false
}
