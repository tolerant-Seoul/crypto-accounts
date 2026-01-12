// Package bip39 implements BIP-39 mnemonic code for generating deterministic keys.
package bip39

import "errors"

var (
	// ErrInvalidEntropyLength is returned when entropy length is not valid.
	// Valid lengths are 128, 160, 192, 224, or 256 bits (16, 20, 24, 28, or 32 bytes).
	ErrInvalidEntropyLength = errors.New("invalid entropy length: must be 128, 160, 192, 224, or 256 bits")

	// ErrInvalidMnemonicLength is returned when mnemonic word count is not valid.
	// Valid word counts are 12, 15, 18, 21, or 24.
	ErrInvalidMnemonicLength = errors.New("invalid mnemonic length: must be 12, 15, 18, 21, or 24 words")

	// ErrInvalidMnemonic is returned when mnemonic contains invalid words.
	ErrInvalidMnemonic = errors.New("invalid mnemonic: contains unknown words")

	// ErrInvalidChecksum is returned when mnemonic checksum verification fails.
	ErrInvalidChecksum = errors.New("invalid mnemonic: checksum mismatch")

	// ErrWordNotFound is returned when a word is not in the word list.
	ErrWordNotFound = errors.New("word not found in word list")
)
