// Package hash provides common cryptographic hash functions used in cryptocurrencies.
package hash

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"

	"golang.org/x/crypto/ripemd160"
)

// SHA256 computes the SHA-256 hash of the input data.
func SHA256(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

// DoubleSHA256 computes SHA256(SHA256(data)), commonly used in Bitcoin.
func DoubleSHA256(data []byte) []byte {
	first := sha256.Sum256(data)
	second := sha256.Sum256(first[:])
	return second[:]
}

// RIPEMD160 computes the RIPEMD-160 hash of the input data.
func RIPEMD160(data []byte) []byte {
	h := ripemd160.New()
	h.Write(data)
	return h.Sum(nil)
}

// Hash160 computes RIPEMD160(SHA256(data)), commonly used for Bitcoin addresses.
func Hash160(data []byte) []byte {
	sha := sha256.Sum256(data)
	return RIPEMD160(sha[:])
}

// HMACSHA512 computes HMAC-SHA512 with the given key and data.
func HMACSHA512(key, data []byte) []byte {
	h := hmac.New(sha512.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// Checksum returns the first 4 bytes of DoubleSHA256, used for address checksums.
func Checksum(data []byte) []byte {
	return DoubleSHA256(data)[:4]
}

// VerifyChecksum verifies that the last 4 bytes match the checksum of the preceding bytes.
func VerifyChecksum(data []byte) bool {
	if len(data) < 4 {
		return false
	}

	payload := data[:len(data)-4]
	checksum := data[len(data)-4:]
	expected := Checksum(payload)

	for i := 0; i < 4; i++ {
		if checksum[i] != expected[i] {
			return false
		}
	}

	return true
}
