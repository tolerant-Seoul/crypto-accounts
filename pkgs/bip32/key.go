// Package bip32 implements BIP-32 Hierarchical Deterministic Wallets.
// Reference: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
package bip32

import (
	"github.com/study/crypto-accounts/pkgs/crypto/hash"
	"github.com/study/crypto-accounts/pkgs/crypto/secp256k1"
)

// HardenedKeyStart is the index at which hardened child keys begin (2^31).
const HardenedKeyStart uint32 = 0x80000000

// Key is the interface for BIP-32 extended keys.
// This interface allows for different implementations and testing (DIP, ISP).
type Key interface {
	// IsPrivate returns true if this is a private key.
	IsPrivate() bool

	// PublicKeyBytes returns the 33-byte compressed public key.
	PublicKeyBytes() []byte

	// PrivateKeyBytes returns the 32-byte private key, or nil if public.
	PrivateKeyBytes() []byte

	// ChainCode returns the 32-byte chain code.
	ChainCode() []byte

	// Depth returns the derivation depth (0 for master).
	Depth() uint8

	// ParentFingerprint returns the 4-byte parent fingerprint.
	ParentFingerprint() []byte

	// ChildIndex returns the child index (0 for master).
	ChildIndex() uint32

	// Network returns the network configuration.
	Network() *Network

	// Child derives a child key at the given index.
	Child(index uint32) (Key, error)

	// Neuter returns the public key version of this key.
	Neuter() (Key, error)

	// Serialize returns the 78-byte serialized key.
	Serialize() []byte

	// String returns the Base58Check encoded key.
	String() string
}

// ExtendedKey implements the Key interface.
type ExtendedKey struct {
	key         []byte   // 33 bytes: 0x00 + private key, or compressed public key
	chainCode   []byte   // 32 bytes
	depth       uint8    // 0 for master
	parentFP    []byte   // 4 bytes
	childIndex  uint32   // 0 for master
	network     *Network // network configuration
	isPrivate   bool
}

// Ensure ExtendedKey implements Key interface
var _ Key = (*ExtendedKey)(nil)

// NewMasterKey creates a new master extended key from a seed.
// The seed should be between 128 and 512 bits (16-64 bytes).
func NewMasterKey(seed []byte) (*ExtendedKey, error) {
	return NewMasterKeyWithNetwork(seed, DefaultNetwork)
}

// NewMasterKeyWithNetwork creates a master key for a specific network.
func NewMasterKeyWithNetwork(seed []byte, network *Network) (*ExtendedKey, error) {
	if len(seed) < 16 || len(seed) > 64 {
		return nil, ErrInvalidSeedLength
	}

	// HMAC-SHA512 with key "Bitcoin seed"
	I := hash.HMACSHA512([]byte("Bitcoin seed"), seed)

	IL := I[:32] // private key
	IR := I[32:] // chain code

	// Validate private key
	if !secp256k1.IsValidPrivateKey(IL) {
		return nil, ErrDerivationFailed
	}

	// Create extended key with 0x00 prefix for private key
	key := make([]byte, 33)
	key[0] = 0x00
	copy(key[1:], IL)

	return &ExtendedKey{
		key:        key,
		chainCode:  IR,
		depth:      0,
		parentFP:   []byte{0x00, 0x00, 0x00, 0x00},
		childIndex: 0,
		network:    network,
		isPrivate:  true,
	}, nil
}

// IsPrivate returns true if this is a private key.
func (k *ExtendedKey) IsPrivate() bool {
	return k.isPrivate
}

// PublicKeyBytes returns the 33-byte compressed public key.
func (k *ExtendedKey) PublicKeyBytes() []byte {
	if !k.isPrivate {
		return k.key
	}
	return secp256k1.PrivateKeyToCompressedPublicKey(k.key[1:])
}

// PrivateKeyBytes returns the 32-byte private key, or nil if public.
func (k *ExtendedKey) PrivateKeyBytes() []byte {
	if !k.isPrivate {
		return nil
	}
	return k.key[1:]
}

// ChainCode returns the 32-byte chain code.
func (k *ExtendedKey) ChainCode() []byte {
	return k.chainCode
}

// Depth returns the derivation depth.
func (k *ExtendedKey) Depth() uint8 {
	return k.depth
}

// ParentFingerprint returns the 4-byte parent fingerprint.
func (k *ExtendedKey) ParentFingerprint() []byte {
	return k.parentFP
}

// ChildIndex returns the child index.
func (k *ExtendedKey) ChildIndex() uint32 {
	return k.childIndex
}

// Network returns the network configuration.
func (k *ExtendedKey) Network() *Network {
	return k.network
}

// Fingerprint returns this key's fingerprint (first 4 bytes of Hash160 of public key).
func (k *ExtendedKey) Fingerprint() []byte {
	return hash.Hash160(k.PublicKeyBytes())[:4]
}

// Hardened returns a hardened index for the given index.
func Hardened(index uint32) uint32 {
	return index + HardenedKeyStart
}

// IsHardened returns true if the index is a hardened index.
func IsHardened(index uint32) bool {
	return index >= HardenedKeyStart
}
