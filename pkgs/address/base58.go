package address

import (
	"bytes"
	"fmt"
	"math/big"
)

// Base58 alphabets for different chains
const (
	// Bitcoin/standard Base58 alphabet
	BitcoinAlphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

	// Ripple Base58 alphabet
	RippleAlphabet = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"

	// Flickr Base58 alphabet (used by some chains)
	FlickrAlphabet = "123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ"
)

// Base58Encoder provides Base58 encoding/decoding
type Base58Encoder struct {
	alphabet   string
	alphabetMap map[byte]int
}

// NewBase58Encoder creates a new Base58 encoder with the given alphabet
func NewBase58Encoder(alphabet string) *Base58Encoder {
	enc := &Base58Encoder{
		alphabet:   alphabet,
		alphabetMap: make(map[byte]int),
	}
	for i := 0; i < len(alphabet); i++ {
		enc.alphabetMap[alphabet[i]] = i
	}
	return enc
}

// defaultBase58 is the Bitcoin Base58 encoder
var defaultBase58 = NewBase58Encoder(BitcoinAlphabet)

// Base58Encode encodes data to Base58 using Bitcoin alphabet
func Base58Encode(data []byte) string {
	return defaultBase58.Encode(data)
}

// Base58Decode decodes Base58 string using Bitcoin alphabet
func Base58Decode(str string) ([]byte, error) {
	return defaultBase58.Decode(str)
}

// Encode encodes data to Base58
func (e *Base58Encoder) Encode(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	// Count leading zeros
	leadingZeros := 0
	for _, b := range data {
		if b == 0 {
			leadingZeros++
		} else {
			break
		}
	}

	// Convert to big integer
	num := new(big.Int).SetBytes(data)
	base := big.NewInt(58)
	zero := big.NewInt(0)
	mod := new(big.Int)

	var result []byte
	for num.Cmp(zero) > 0 {
		num.DivMod(num, base, mod)
		result = append(result, e.alphabet[mod.Int64()])
	}

	// Add leading zeros
	for i := 0; i < leadingZeros; i++ {
		result = append(result, e.alphabet[0])
	}

	// Reverse the result
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}

	return string(result)
}

// Decode decodes a Base58 string
func (e *Base58Encoder) Decode(str string) ([]byte, error) {
	if len(str) == 0 {
		return nil, nil
	}

	// Count leading alphabet[0] characters
	leadingZeros := 0
	for _, c := range str {
		if c == rune(e.alphabet[0]) {
			leadingZeros++
		} else {
			break
		}
	}

	// Convert from base58 to big integer
	num := big.NewInt(0)
	base := big.NewInt(58)

	for _, c := range str {
		idx, ok := e.alphabetMap[byte(c)]
		if !ok {
			return nil, fmt.Errorf("invalid character '%c' in Base58 string", c)
		}
		num.Mul(num, base)
		num.Add(num, big.NewInt(int64(idx)))
	}

	// Convert to bytes
	decoded := num.Bytes()

	// Add leading zeros
	result := make([]byte, leadingZeros+len(decoded))
	copy(result[leadingZeros:], decoded)

	return result, nil
}

// Base58CheckEncode encodes data with version byte and checksum
func Base58CheckEncode(version byte, payload []byte) string {
	data := make([]byte, 1+len(payload))
	data[0] = version
	copy(data[1:], payload)

	checksum := Checksum4(data)
	data = append(data, checksum...)

	return Base58Encode(data)
}

// Base58CheckDecode decodes a Base58Check encoded string
func Base58CheckDecode(str string) (version byte, payload []byte, err error) {
	decoded, err := Base58Decode(str)
	if err != nil {
		return 0, nil, err
	}

	if len(decoded) < 5 {
		return 0, nil, ErrInvalidAddress
	}

	// Split into version, payload, and checksum
	version = decoded[0]
	payload = decoded[1 : len(decoded)-4]
	checksum := decoded[len(decoded)-4:]

	// Verify checksum
	expectedChecksum := Checksum4(decoded[:len(decoded)-4])
	if !bytes.Equal(checksum, expectedChecksum) {
		return 0, nil, ErrInvalidChecksum
	}

	return version, payload, nil
}

// Base58CheckEncodeMultiVersion encodes with multi-byte version prefix
func Base58CheckEncodeMultiVersion(versionPrefix []byte, payload []byte) string {
	data := make([]byte, len(versionPrefix)+len(payload))
	copy(data, versionPrefix)
	copy(data[len(versionPrefix):], payload)

	checksum := Checksum4(data)
	data = append(data, checksum...)

	return Base58Encode(data)
}
