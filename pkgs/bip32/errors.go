package bip32

import "errors"

var (
	// ErrInvalidSeedLength indicates the seed length is outside the valid range (16-64 bytes).
	ErrInvalidSeedLength = errors.New("bip32: seed length must be between 128 and 512 bits")

	// ErrInvalidKeyData indicates the key data is malformed or invalid.
	ErrInvalidKeyData = errors.New("bip32: invalid key data")

	// ErrHardenedFromPublic indicates an attempt to derive a hardened child from a public key.
	ErrHardenedFromPublic = errors.New("bip32: cannot derive hardened child from public key")

	// ErrDerivationFailed indicates the key derivation produced an invalid result.
	ErrDerivationFailed = errors.New("bip32: key derivation failed")

	// ErrInvalidPath indicates an invalid derivation path format.
	ErrInvalidPath = errors.New("bip32: invalid derivation path")

	// ErrInvalidSerializedKey indicates the serialized key data is malformed.
	ErrInvalidSerializedKey = errors.New("bip32: invalid serialized key")
)
