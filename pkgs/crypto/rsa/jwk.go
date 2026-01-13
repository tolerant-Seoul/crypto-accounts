// Package rsa provides JWK (JSON Web Key) support for Arweave wallets
package rsa

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
)

// JWK represents a JSON Web Key for RSA
// This is the format used by Arweave wallet files
type JWK struct {
	Kty string `json:"kty"`           // Key type: "RSA"
	N   string `json:"n"`             // Modulus (Base64URL)
	E   string `json:"e"`             // Public exponent (Base64URL)
	D   string `json:"d,omitempty"`   // Private exponent (Base64URL)
	P   string `json:"p,omitempty"`   // First prime factor (Base64URL)
	Q   string `json:"q,omitempty"`   // Second prime factor (Base64URL)
	Dp  string `json:"dp,omitempty"`  // d mod (p-1) (Base64URL)
	Dq  string `json:"dq,omitempty"`  // d mod (q-1) (Base64URL)
	Qi  string `json:"qi,omitempty"`  // (q^-1) mod p (Base64URL)
}

// PrivateKeyToJWK converts an RSA private key to JWK format
func PrivateKeyToJWK(key *rsa.PrivateKey) *JWK {
	return &JWK{
		Kty: "RSA",
		N:   base64URLEncode(key.N.Bytes()),
		E:   base64URLEncode(big.NewInt(int64(key.E)).Bytes()),
		D:   base64URLEncode(key.D.Bytes()),
		P:   base64URLEncode(key.Primes[0].Bytes()),
		Q:   base64URLEncode(key.Primes[1].Bytes()),
		Dp:  base64URLEncode(key.Precomputed.Dp.Bytes()),
		Dq:  base64URLEncode(key.Precomputed.Dq.Bytes()),
		Qi:  base64URLEncode(key.Precomputed.Qinv.Bytes()),
	}
}

// PublicKeyToJWK converts an RSA public key to JWK format
func PublicKeyToJWK(key *rsa.PublicKey) *JWK {
	return &JWK{
		Kty: "RSA",
		N:   base64URLEncode(key.N.Bytes()),
		E:   base64URLEncode(big.NewInt(int64(key.E)).Bytes()),
	}
}

// ToPrivateKey converts a JWK to an RSA private key
func (j *JWK) ToPrivateKey() (*rsa.PrivateKey, error) {
	if j.Kty != "RSA" {
		return nil, fmt.Errorf("invalid key type: %s (expected RSA)", j.Kty)
	}

	n, err := base64URLDecode(j.N)
	if err != nil {
		return nil, fmt.Errorf("invalid modulus: %w", err)
	}

	e, err := base64URLDecode(j.E)
	if err != nil {
		return nil, fmt.Errorf("invalid exponent: %w", err)
	}

	d, err := base64URLDecode(j.D)
	if err != nil {
		return nil, fmt.Errorf("invalid private exponent: %w", err)
	}

	p, err := base64URLDecode(j.P)
	if err != nil {
		return nil, fmt.Errorf("invalid prime p: %w", err)
	}

	q, err := base64URLDecode(j.Q)
	if err != nil {
		return nil, fmt.Errorf("invalid prime q: %w", err)
	}

	dp, err := base64URLDecode(j.Dp)
	if err != nil {
		return nil, fmt.Errorf("invalid dp: %w", err)
	}

	dq, err := base64URLDecode(j.Dq)
	if err != nil {
		return nil, fmt.Errorf("invalid dq: %w", err)
	}

	qi, err := base64URLDecode(j.Qi)
	if err != nil {
		return nil, fmt.Errorf("invalid qi: %w", err)
	}

	key := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: new(big.Int).SetBytes(n),
			E: int(new(big.Int).SetBytes(e).Int64()),
		},
		D:      new(big.Int).SetBytes(d),
		Primes: []*big.Int{new(big.Int).SetBytes(p), new(big.Int).SetBytes(q)},
		Precomputed: rsa.PrecomputedValues{
			Dp:   new(big.Int).SetBytes(dp),
			Dq:   new(big.Int).SetBytes(dq),
			Qinv: new(big.Int).SetBytes(qi),
		},
	}

	// Validate the key
	if err := key.Validate(); err != nil {
		return nil, fmt.Errorf("invalid key: %w", err)
	}

	return key, nil
}

// ToPublicKey converts a JWK to an RSA public key
func (j *JWK) ToPublicKey() (*rsa.PublicKey, error) {
	if j.Kty != "RSA" {
		return nil, fmt.Errorf("invalid key type: %s (expected RSA)", j.Kty)
	}

	n, err := base64URLDecode(j.N)
	if err != nil {
		return nil, fmt.Errorf("invalid modulus: %w", err)
	}

	e, err := base64URLDecode(j.E)
	if err != nil {
		return nil, fmt.Errorf("invalid exponent: %w", err)
	}

	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(n),
		E: int(new(big.Int).SetBytes(e).Int64()),
	}, nil
}

// ToJSON converts a JWK to JSON string
func (j *JWK) ToJSON() (string, error) {
	data, err := json.MarshalIndent(j, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// JWKFromJSON parses a JWK from JSON
func JWKFromJSON(data string) (*JWK, error) {
	var jwk JWK
	if err := json.Unmarshal([]byte(data), &jwk); err != nil {
		return nil, fmt.Errorf("invalid JWK JSON: %w", err)
	}
	return &jwk, nil
}

// PrivateKeyFromJWKJSON parses an RSA private key from JWK JSON
func PrivateKeyFromJWKJSON(data string) (*rsa.PrivateKey, error) {
	jwk, err := JWKFromJSON(data)
	if err != nil {
		return nil, err
	}
	return jwk.ToPrivateKey()
}

// base64URLEncode encodes bytes to Base64URL without padding
func base64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// base64URLDecode decodes Base64URL (with or without padding)
func base64URLDecode(s string) ([]byte, error) {
	// Try without padding first
	data, err := base64.RawURLEncoding.DecodeString(s)
	if err == nil {
		return data, nil
	}

	// Try with padding
	return base64.URLEncoding.DecodeString(s)
}

// GetArweaveOwner returns the "owner" field used in Arweave transactions
// This is the Base64URL-encoded modulus
func GetArweaveOwner(key *rsa.PublicKey) string {
	return base64URLEncode(key.N.Bytes())
}
