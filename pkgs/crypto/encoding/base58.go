// Package encoding provides encoding/decoding utilities for cryptocurrencies.
package encoding

import (
	"errors"
	"math/big"

	"github.com/study/crypto-accounts/pkgs/crypto/hash"
)

// Base58 alphabet used by Bitcoin (excludes 0, O, I, l to avoid confusion)
const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

var (
	ErrInvalidBase58     = errors.New("invalid base58 string")
	ErrInvalidChecksum   = errors.New("invalid checksum")
	ErrInvalidDataLength = errors.New("invalid data length")
)

// alphabetMap maps characters to their base58 values
var alphabetMap = func() map[byte]int64 {
	m := make(map[byte]int64)
	for i, c := range base58Alphabet {
		m[byte(c)] = int64(i)
	}
	return m
}()

// Base58Encode encodes bytes to a Base58 string.
func Base58Encode(input []byte) string {
	if len(input) == 0 {
		return ""
	}

	// Count leading zeros
	leadingZeros := countLeadingZeros(input)

	// Convert to big integer
	num := new(big.Int).SetBytes(input)
	base := big.NewInt(58)
	zero := big.NewInt(0)
	mod := new(big.Int)

	// Convert to base58
	var result []byte
	for num.Cmp(zero) > 0 {
		num.DivMod(num, base, mod)
		result = append(result, base58Alphabet[mod.Int64()])
	}

	// Add leading '1's for each leading zero byte
	for i := 0; i < leadingZeros; i++ {
		result = append(result, '1')
	}

	// Reverse the result
	reverse(result)

	return string(result)
}

// Base58Decode decodes a Base58 string to bytes.
func Base58Decode(input string) ([]byte, error) {
	if len(input) == 0 {
		return nil, nil
	}

	// Count leading '1's
	leadingOnes := 0
	for _, c := range input {
		if c != '1' {
			break
		}
		leadingOnes++
	}

	// Convert from base58 to big integer
	num := big.NewInt(0)
	base := big.NewInt(58)

	for _, c := range input {
		val, ok := alphabetMap[byte(c)]
		if !ok {
			return nil, ErrInvalidBase58
		}
		num.Mul(num, base)
		num.Add(num, big.NewInt(val))
	}

	// Convert to bytes
	decoded := num.Bytes()

	// Add leading zeros
	result := make([]byte, leadingOnes+len(decoded))
	copy(result[leadingOnes:], decoded)

	return result, nil
}

// Base58CheckEncode encodes bytes with a 4-byte checksum appended.
func Base58CheckEncode(input []byte) string {
	checksum := hash.Checksum(input)
	return Base58Encode(append(input, checksum...))
}

// Base58CheckDecode decodes a Base58Check string and verifies the checksum.
func Base58CheckDecode(input string) ([]byte, error) {
	decoded, err := Base58Decode(input)
	if err != nil {
		return nil, err
	}

	if len(decoded) < 4 {
		return nil, ErrInvalidDataLength
	}

	// Verify checksum
	if !hash.VerifyChecksum(decoded) {
		return nil, ErrInvalidChecksum
	}

	// Return payload without checksum
	return decoded[:len(decoded)-4], nil
}

// Helper functions

func countLeadingZeros(data []byte) int {
	count := 0
	for _, b := range data {
		if b != 0 {
			break
		}
		count++
	}
	return count
}

func reverse(data []byte) {
	for i, j := 0, len(data)-1; i < j; i, j = i+1, j-1 {
		data[i], data[j] = data[j], data[i]
	}
}
