// Package rsa provides RSA key generation and management for Arweave
package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
)

// KeySize represents RSA key sizes
type KeySize int

const (
	// KeySize2048 is 2048-bit RSA (minimum for Arweave)
	KeySize2048 KeySize = 2048
	// KeySize4096 is 4096-bit RSA (recommended for Arweave)
	KeySize4096 KeySize = 4096
)

// GenerateKey generates a new RSA key pair
func GenerateKey(bits KeySize) (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, int(bits))
}

// GenerateArweaveKey generates a 4096-bit RSA key for Arweave
func GenerateArweaveKey() (*rsa.PrivateKey, error) {
	return GenerateKey(KeySize4096)
}

// PrivateKeyToBytes converts an RSA private key to PKCS#1 DER format
func PrivateKeyToBytes(key *rsa.PrivateKey) []byte {
	return x509.MarshalPKCS1PrivateKey(key)
}

// PrivateKeyFromBytes parses an RSA private key from PKCS#1 DER format
func PrivateKeyFromBytes(data []byte) (*rsa.PrivateKey, error) {
	return x509.ParsePKCS1PrivateKey(data)
}

// PrivateKeyToPEM encodes an RSA private key to PEM format
func PrivateKeyToPEM(key *rsa.PrivateKey) []byte {
	der := x509.MarshalPKCS1PrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: der,
	})
}

// PrivateKeyFromPEM parses an RSA private key from PEM format
func PrivateKeyFromPEM(pemData []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	if block.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("unexpected PEM type: %s", block.Type)
	}

	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// PublicKeyToBytes returns the modulus (n) of the RSA public key
// This is what Arweave uses for address generation
func PublicKeyToBytes(key *rsa.PublicKey) []byte {
	return key.N.Bytes()
}

// PublicKeyFromPrivate extracts the public key from a private key
func PublicKeyFromPrivate(key *rsa.PrivateKey) *rsa.PublicKey {
	return &key.PublicKey
}

// GetModulus returns the modulus (n) of an RSA key as bytes
// Arweave addresses are derived from the SHA-256 hash of this modulus
func GetModulus(key *rsa.PublicKey) []byte {
	return key.N.Bytes()
}

// GetExponent returns the public exponent (e) of an RSA key
func GetExponent(key *rsa.PublicKey) int {
	return key.E
}

// ArweaveAddressHash computes the SHA-256 hash used for Arweave addresses
func ArweaveAddressHash(modulus []byte) []byte {
	hash := sha256.Sum256(modulus)
	return hash[:]
}

// PrivateKeyFromModulusAndExponents reconstructs an RSA private key from components
// This is useful for importing keys from JWK format (used by Arweave wallets)
func PrivateKeyFromComponents(n, e, d, p, q, dp, dq, qinv *big.Int) *rsa.PrivateKey {
	return &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: n,
			E: int(e.Int64()),
		},
		D:      d,
		Primes: []*big.Int{p, q},
		Precomputed: rsa.PrecomputedValues{
			Dp:        dp,
			Dq:        dq,
			Qinv:      qinv,
			CRTValues: []rsa.CRTValue{},
		},
	}
}

// ValidateKeySize checks if the key size is suitable for Arweave
func ValidateKeySize(key *rsa.PublicKey) error {
	bits := key.N.BitLen()
	if bits < 2048 {
		return fmt.Errorf("RSA key too small: %d bits (minimum 2048)", bits)
	}
	return nil
}

// KeyInfo contains information about an RSA key
type KeyInfo struct {
	BitSize  int
	Modulus  []byte
	Exponent int
}

// GetKeyInfo returns information about an RSA public key
func GetKeyInfo(key *rsa.PublicKey) *KeyInfo {
	return &KeyInfo{
		BitSize:  key.N.BitLen(),
		Modulus:  key.N.Bytes(),
		Exponent: key.E,
	}
}
