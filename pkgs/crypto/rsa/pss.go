// Package rsa provides RSA-PSS signing for Arweave transactions
package rsa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
)

// PSS provides RSA-PSS signing operations
type PSS struct {
	key *rsa.PrivateKey
}

// NewPSS creates a new PSS signer with the given private key
func NewPSS(key *rsa.PrivateKey) *PSS {
	return &PSS{key: key}
}

// Sign signs data using RSA-PSS with SHA-256
// This is the signing scheme used by Arweave
func (p *PSS) Sign(data []byte) ([]byte, error) {
	if p.key == nil {
		return nil, fmt.Errorf("no private key set")
	}

	// Hash the data with SHA-256
	hash := sha256.Sum256(data)

	// Sign using RSA-PSS
	opts := &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       crypto.SHA256,
	}

	signature, err := rsa.SignPSS(rand.Reader, p.key, crypto.SHA256, hash[:], opts)
	if err != nil {
		return nil, fmt.Errorf("signing failed: %w", err)
	}

	return signature, nil
}

// Verify verifies a signature using RSA-PSS with SHA-256
func (p *PSS) Verify(data, signature []byte) bool {
	return VerifyPSS(&p.key.PublicKey, data, signature)
}

// SignWithKey signs data using the provided RSA private key
func SignWithKey(key *rsa.PrivateKey, data []byte) ([]byte, error) {
	pss := NewPSS(key)
	return pss.Sign(data)
}

// VerifyPSS verifies a signature using an RSA public key
func VerifyPSS(key *rsa.PublicKey, data, signature []byte) bool {
	hash := sha256.Sum256(data)

	opts := &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       crypto.SHA256,
	}

	err := rsa.VerifyPSS(key, crypto.SHA256, hash[:], signature, opts)
	return err == nil
}

// ArweaveSignatureSize returns the expected signature size for a given key
func ArweaveSignatureSize(key *rsa.PublicKey) int {
	// RSA signature size equals the modulus size
	return (key.N.BitLen() + 7) / 8
}
