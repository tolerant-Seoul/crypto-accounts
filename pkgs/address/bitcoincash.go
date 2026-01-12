package address

import (
	"fmt"
	"strings"
)

// Bitcoin Cash address types
const (
	BCHTypeP2PKH byte = 0x00
	BCHTypeP2SH  byte = 0x08
)

// CashAddr charset
const cashAddrCharset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

// BitcoinCashAddress generates Bitcoin Cash CashAddr format addresses
type BitcoinCashAddress struct {
	testnet bool
}

// NewBitcoinCashAddress creates a new Bitcoin Cash address generator
func NewBitcoinCashAddress(testnet bool) *BitcoinCashAddress {
	return &BitcoinCashAddress{testnet: testnet}
}

// ChainID returns the chain identifier
func (b *BitcoinCashAddress) ChainID() ChainID {
	return ChainBitcoinCash
}

// Generate creates a CashAddr from a public key
func (b *BitcoinCashAddress) Generate(publicKey []byte) (string, error) {
	if len(publicKey) != 33 && len(publicKey) != 65 {
		return "", ErrInvalidPublicKey
	}

	// Hash160 of public key
	hash := Hash160(publicKey)

	return b.encodeCashAddr(BCHTypeP2PKH, hash)
}

// P2PKH generates a P2PKH CashAddr
func (b *BitcoinCashAddress) P2PKH(publicKey []byte) (string, error) {
	return b.Generate(publicKey)
}

// P2SH generates a P2SH CashAddr from a script hash
func (b *BitcoinCashAddress) P2SH(scriptHash []byte) (string, error) {
	if len(scriptHash) != 20 {
		return "", fmt.Errorf("script hash must be 20 bytes")
	}
	return b.encodeCashAddr(BCHTypeP2SH, scriptHash)
}

// encodeCashAddr encodes data in CashAddr format
func (b *BitcoinCashAddress) encodeCashAddr(addrType byte, hash []byte) (string, error) {
	// Get prefix
	prefix := "bitcoincash"
	if b.testnet {
		prefix = "bchtest"
	}

	// Create version byte (type + size bits)
	// For 20-byte hash: size = 0
	versionByte := addrType // Type in upper 4 bits, size in lower 4 bits

	// Combine version byte and hash
	payload := make([]byte, 1+len(hash))
	payload[0] = versionByte
	copy(payload[1:], hash)

	// Convert to 5-bit groups
	converted, err := ConvertBitsBytes(payload, 8, 5, true)
	if err != nil {
		return "", err
	}

	// Calculate checksum
	checksum := cashAddrChecksum(prefix, converted)

	// Combine data and checksum
	combined := append(converted, checksum...)

	// Encode to CashAddr charset
	var result strings.Builder
	result.WriteString(prefix)
	result.WriteByte(':')
	for _, d := range combined {
		result.WriteByte(cashAddrCharset[d])
	}

	return result.String(), nil
}

// cashAddrChecksum calculates the CashAddr checksum
func cashAddrChecksum(prefix string, data []int) []int {
	// Expand prefix
	prefixData := make([]int, len(prefix)+1)
	for i, c := range prefix {
		prefixData[i] = int(c) & 0x1f
	}
	prefixData[len(prefix)] = 0

	// Combine prefix and data, add 8 zeros for checksum
	values := append(prefixData, data...)
	values = append(values, 0, 0, 0, 0, 0, 0, 0, 0)

	// Calculate polymod
	polymod := cashAddrPolymod(values) ^ 1

	// Extract checksum
	checksum := make([]int, 8)
	for i := 0; i < 8; i++ {
		checksum[i] = (polymod >> uint(5*(7-i))) & 0x1f
	}

	return checksum
}

// cashAddrPolymod calculates the BCH polymod
func cashAddrPolymod(values []int) int {
	generator := []int{
		0x98f2bc8e61,
		0x79b76d99e2,
		0xf33e5fb3c4,
		0xae2eabe2a8,
		0x1e4f43e470,
	}

	chk := 1
	for _, v := range values {
		top := chk >> 35
		chk = ((chk & 0x07ffffffff) << 5) ^ v
		for i := 0; i < 5; i++ {
			if (top>>uint(i))&1 == 1 {
				chk ^= generator[i]
			}
		}
	}
	return chk
}

// Validate checks if a CashAddr is valid
func (b *BitcoinCashAddress) Validate(address string) bool {
	// Remove prefix if present
	lower := strings.ToLower(address)

	var prefix, data string
	if strings.Contains(lower, ":") {
		parts := strings.SplitN(lower, ":", 2)
		prefix = parts[0]
		data = parts[1]
	} else {
		// Assume mainnet
		prefix = "bitcoincash"
		data = lower
	}

	// Check prefix
	expectedPrefix := "bitcoincash"
	if b.testnet {
		expectedPrefix = "bchtest"
	}
	if prefix != expectedPrefix {
		return false
	}

	// Decode data
	decoded := make([]int, len(data))
	for i, c := range []byte(data) {
		idx := strings.IndexByte(cashAddrCharset, c)
		if idx < 0 {
			return false
		}
		decoded[i] = idx
	}

	// Verify checksum
	prefixData := make([]int, len(prefix)+1)
	for i, c := range prefix {
		prefixData[i] = int(c) & 0x1f
	}
	prefixData[len(prefix)] = 0

	values := append(prefixData, decoded...)
	return cashAddrPolymod(values) == 0
}

// ToLegacy converts a CashAddr to legacy Bitcoin address format
func (b *BitcoinCashAddress) ToLegacy(cashAddr string) (string, error) {
	// This would decode the CashAddr and re-encode as Base58Check
	// Simplified implementation
	return "", fmt.Errorf("legacy conversion not implemented")
}
