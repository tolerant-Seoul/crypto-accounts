package address

import (
	"crypto/sha256"
	"crypto/sha512"

	"golang.org/x/crypto/ripemd160"
	"golang.org/x/crypto/sha3"
	"golang.org/x/crypto/blake2b"
)

// Hash160 performs SHA256 followed by RIPEMD160 (Bitcoin-style)
func Hash160(data []byte) []byte {
	sha := sha256.Sum256(data)
	ripemd := ripemd160.New()
	ripemd.Write(sha[:])
	return ripemd.Sum(nil)
}

// DoubleSHA256 performs SHA256 twice (Bitcoin-style)
func DoubleSHA256(data []byte) []byte {
	first := sha256.Sum256(data)
	second := sha256.Sum256(first[:])
	return second[:]
}

// SHA256Hash performs a single SHA256 hash
func SHA256Hash(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

// SHA512Hash performs a single SHA512 hash
func SHA512Hash(data []byte) []byte {
	hash := sha512.Sum512(data)
	return hash[:]
}

// Keccak256 performs Keccak-256 hash (Ethereum-style)
func Keccak256(data []byte) []byte {
	hash := sha3.NewLegacyKeccak256()
	hash.Write(data)
	return hash.Sum(nil)
}

// SHA3256 performs SHA3-256 hash
func SHA3256(data []byte) []byte {
	hash := sha3.New256()
	hash.Write(data)
	return hash.Sum(nil)
}

// Blake2b256 performs BLAKE2b-256 hash
func Blake2b256(data []byte) []byte {
	hash, _ := blake2b.New256(nil)
	hash.Write(data)
	return hash.Sum(nil)
}

// Blake2b512 performs BLAKE2b-512 hash
func Blake2b512(data []byte) []byte {
	hash, _ := blake2b.New512(nil)
	hash.Write(data)
	return hash.Sum(nil)
}

// Blake2b160 performs BLAKE2b-160 hash (Filecoin-style)
func Blake2b160(data []byte) []byte {
	hash, _ := blake2b.New(20, nil)
	hash.Write(data)
	return hash.Sum(nil)
}

// RIPEMD160Hash performs RIPEMD-160 hash
func RIPEMD160Hash(data []byte) []byte {
	hash := ripemd160.New()
	hash.Write(data)
	return hash.Sum(nil)
}

// Checksum4 calculates a 4-byte checksum using double SHA256
func Checksum4(data []byte) []byte {
	return DoubleSHA256(data)[:4]
}

// Checksum4Keccak calculates a 4-byte checksum using Keccak256
func Checksum4Keccak(data []byte) []byte {
	return Keccak256(data)[:4]
}
