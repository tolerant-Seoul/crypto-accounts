package address

import (
	"fmt"
	"strings"
)

// Bech32 constants
const (
	bech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
)

var bech32CharsetMap = func() map[byte]int {
	m := make(map[byte]int)
	for i, c := range []byte(bech32Charset) {
		m[c] = i
	}
	return m
}()

// Bech32Encoding represents the Bech32 variant
type Bech32Encoding int

const (
	Bech32Standard Bech32Encoding = iota // BIP-173
	Bech32m                              // BIP-350
)

// bech32Polymod calculates the Bech32 polymod checksum
func bech32Polymod(values []int) int {
	generator := []int{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	chk := 1
	for _, v := range values {
		top := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ v
		for i := 0; i < 5; i++ {
			if (top>>uint(i))&1 == 1 {
				chk ^= generator[i]
			}
		}
	}
	return chk
}

// bech32HRPExpand expands the human-readable part for checksum calculation
func bech32HRPExpand(hrp string) []int {
	result := make([]int, len(hrp)*2+1)
	for i, c := range hrp {
		result[i] = int(c) >> 5
		result[i+len(hrp)+1] = int(c) & 31
	}
	result[len(hrp)] = 0
	return result
}

// bech32VerifyChecksum verifies the Bech32 checksum
func bech32VerifyChecksum(hrp string, data []int, encoding Bech32Encoding) bool {
	values := append(bech32HRPExpand(hrp), data...)
	expectedConst := 1
	if encoding == Bech32m {
		expectedConst = 0x2bc830a3
	}
	return bech32Polymod(values) == expectedConst
}

// bech32CreateChecksum creates a Bech32 checksum
func bech32CreateChecksum(hrp string, data []int, encoding Bech32Encoding) []int {
	values := append(bech32HRPExpand(hrp), data...)
	values = append(values, 0, 0, 0, 0, 0, 0)
	polymod := bech32Polymod(values)
	expectedConst := 1
	if encoding == Bech32m {
		expectedConst = 0x2bc830a3
	}
	polymod ^= expectedConst
	checksum := make([]int, 6)
	for i := 0; i < 6; i++ {
		checksum[i] = (polymod >> uint(5*(5-i))) & 31
	}
	return checksum
}

// Bech32Encode encodes data in Bech32 format
func Bech32Encode(hrp string, data []byte, encoding Bech32Encoding) (string, error) {
	// Convert 8-bit data to 5-bit groups
	intData := make([]int, len(data))
	for i, b := range data {
		intData[i] = int(b)
	}
	converted, err := convertBits(intData, 8, 5, true)
	if err != nil {
		return "", err
	}

	// Create checksum
	checksum := bech32CreateChecksum(hrp, converted, encoding)

	// Build result
	result := strings.Builder{}
	result.WriteString(strings.ToLower(hrp))
	result.WriteByte('1')

	for _, d := range converted {
		result.WriteByte(bech32Charset[d])
	}
	for _, c := range checksum {
		result.WriteByte(bech32Charset[c])
	}

	return result.String(), nil
}

// Bech32Decode decodes a Bech32 string
func Bech32Decode(str string) (hrp string, data []byte, encoding Bech32Encoding, err error) {
	// Check for mixed case
	lower := strings.ToLower(str)
	upper := strings.ToUpper(str)
	if str != lower && str != upper {
		return "", nil, 0, fmt.Errorf("mixed case in bech32 string")
	}
	str = lower

	// Find the separator
	pos := strings.LastIndex(str, "1")
	if pos < 1 || pos+7 > len(str) {
		return "", nil, 0, fmt.Errorf("invalid bech32 separator position")
	}

	hrp = str[:pos]
	dataStr := str[pos+1:]

	// Decode data part
	intData := make([]int, len(dataStr))
	for i, c := range []byte(dataStr) {
		idx, ok := bech32CharsetMap[c]
		if !ok {
			return "", nil, 0, fmt.Errorf("invalid character '%c' in bech32 string", c)
		}
		intData[i] = idx
	}

	// Verify checksum for both encodings
	if bech32VerifyChecksum(hrp, intData, Bech32Standard) {
		encoding = Bech32Standard
	} else if bech32VerifyChecksum(hrp, intData, Bech32m) {
		encoding = Bech32m
	} else {
		return "", nil, 0, ErrInvalidChecksum
	}

	// Remove checksum and convert back to 8-bit
	converted, err := convertBits(intData[:len(intData)-6], 5, 8, false)
	if err != nil {
		return "", nil, 0, err
	}

	// Convert []int to []byte
	result := make([]byte, len(converted))
	for i, v := range converted {
		result[i] = byte(v)
	}

	return hrp, result, encoding, nil
}

// convertBits converts between bit groupings
func convertBits(data []int, fromBits, toBits int, pad bool) ([]int, error) {
	acc := 0
	bits := 0
	maxv := (1 << toBits) - 1
	var result []int

	for _, value := range data {
		if value < 0 || value>>fromBits != 0 {
			return nil, fmt.Errorf("invalid value %d", value)
		}
		acc = (acc << fromBits) | value
		bits += fromBits
		for bits >= toBits {
			bits -= toBits
			result = append(result, (acc>>bits)&maxv)
		}
	}

	if pad {
		if bits > 0 {
			result = append(result, (acc<<(toBits-bits))&maxv)
		}
	} else if bits >= fromBits || ((acc<<(toBits-bits))&maxv) != 0 {
		return nil, fmt.Errorf("invalid padding")
	}

	return result, nil
}

// ConvertBitsBytes converts between bit groupings for byte slices
func ConvertBitsBytes(data []byte, fromBits, toBits int, pad bool) ([]int, error) {
	intData := make([]int, len(data))
	for i, b := range data {
		intData[i] = int(b)
	}
	return convertBits(intData, fromBits, toBits, pad)
}

// SegWitEncode encodes a SegWit address
func SegWitEncode(hrp string, witnessVersion int, witnessProgram []byte) (string, error) {
	if witnessVersion < 0 || witnessVersion > 16 {
		return "", fmt.Errorf("invalid witness version: %d", witnessVersion)
	}

	// Convert witness program to 5-bit groups
	converted, err := ConvertBitsBytes(witnessProgram, 8, 5, true)
	if err != nil {
		return "", err
	}

	// Prepend witness version
	data := append([]int{witnessVersion}, converted...)

	// Determine encoding based on witness version
	encoding := Bech32Standard
	if witnessVersion > 0 {
		encoding = Bech32m
	}

	// Create checksum
	checksum := bech32CreateChecksum(hrp, data, encoding)

	// Build result
	result := strings.Builder{}
	result.WriteString(strings.ToLower(hrp))
	result.WriteByte('1')

	for _, d := range data {
		result.WriteByte(bech32Charset[d])
	}
	for _, c := range checksum {
		result.WriteByte(bech32Charset[c])
	}

	return result.String(), nil
}

// SegWitDecode decodes a SegWit address
func SegWitDecode(str string) (hrp string, witnessVersion int, witnessProgram []byte, err error) {
	hrp, data, encoding, err := Bech32Decode(str)
	if err != nil {
		return "", 0, nil, err
	}

	if len(data) < 1 {
		return "", 0, nil, fmt.Errorf("empty data")
	}

	// Get witness version from decoded data before conversion
	lower := strings.ToLower(str)
	pos := strings.LastIndex(lower, "1")
	dataStr := lower[pos+1:]
	witnessVersion = bech32CharsetMap[dataStr[0]]

	// Verify encoding matches version
	if witnessVersion == 0 && encoding != Bech32Standard {
		return "", 0, nil, fmt.Errorf("invalid encoding for witness version 0")
	}
	if witnessVersion > 0 && encoding != Bech32m {
		return "", 0, nil, fmt.Errorf("invalid encoding for witness version > 0")
	}

	// The data returned from Bech32Decode already has the witness version as the first byte
	// but since we converted from 5-bit to 8-bit, we need to decode differently

	// Re-decode to get 5-bit data
	intData := make([]int, len(dataStr))
	for i, c := range []byte(dataStr) {
		intData[i] = bech32CharsetMap[c]
	}

	// Remove checksum and witness version
	programData := intData[1 : len(intData)-6]

	// Convert 5-bit to 8-bit
	program, err := convertBits(programData, 5, 8, false)
	if err != nil {
		return "", 0, nil, err
	}

	witnessProgram = make([]byte, len(program))
	for i, v := range program {
		witnessProgram[i] = byte(v)
	}

	return hrp, witnessVersion, witnessProgram, nil
}
