package secp256k1

import (
	"errors"
	"math/big"
)

const (
	// CompressedPubKeyLen is the length of a compressed public key
	CompressedPubKeyLen = 33

	// UncompressedPubKeyLen is the length of an uncompressed public key
	UncompressedPubKeyLen = 65

	// PrefixEven is the prefix for compressed public keys with even Y
	PrefixEven byte = 0x02

	// PrefixOdd is the prefix for compressed public keys with odd Y
	PrefixOdd byte = 0x03

	// PrefixUncompressed is the prefix for uncompressed public keys
	PrefixUncompressed byte = 0x04
)

var (
	ErrInvalidPublicKey = errors.New("invalid public key")
)

// CompressPoint compresses an elliptic curve point to 33 bytes.
func CompressPoint(p *Point) []byte {
	result := make([]byte, CompressedPubKeyLen)

	if p.Y.Bit(0) == 0 {
		result[0] = PrefixEven
	} else {
		result[0] = PrefixOdd
	}

	xBytes := p.X.Bytes()
	copy(result[CompressedPubKeyLen-len(xBytes):], xBytes)

	return result
}

// DecompressPoint decompresses a 33-byte compressed public key to a Point.
func DecompressPoint(compressed []byte) (*Point, error) {
	if len(compressed) != CompressedPubKeyLen {
		return nil, ErrInvalidPublicKey
	}

	prefix := compressed[0]
	if prefix != PrefixEven && prefix != PrefixOdd {
		return nil, ErrInvalidPublicKey
	}

	x := new(big.Int).SetBytes(compressed[1:])

	// y^2 = x^3 + 7 (secp256k1: a=0, b=7)
	x3 := new(big.Int).Exp(x, big.NewInt(3), P)
	y2 := new(big.Int).Add(x3, big.NewInt(7))
	y2.Mod(y2, P)

	// y = sqrt(y^2) mod P
	y := new(big.Int).ModSqrt(y2, P)
	if y == nil {
		return nil, ErrInvalidPublicKey
	}

	// Choose correct y based on prefix
	yIsOdd := y.Bit(0) == 1
	prefixIndicatesOdd := prefix == PrefixOdd

	if yIsOdd != prefixIndicatesOdd {
		y.Sub(P, y)
	}

	return &Point{X: x, Y: y}, nil
}

// ParsePublicKey parses a public key from bytes (compressed or uncompressed).
func ParsePublicKey(data []byte) (*Point, error) {
	switch len(data) {
	case CompressedPubKeyLen:
		return DecompressPoint(data)

	case UncompressedPubKeyLen:
		if data[0] != PrefixUncompressed {
			return nil, ErrInvalidPublicKey
		}
		x := new(big.Int).SetBytes(data[1:33])
		y := new(big.Int).SetBytes(data[33:65])
		return &Point{X: x, Y: y}, nil

	default:
		return nil, ErrInvalidPublicKey
	}
}

// SerializeUncompressed serializes a point to 65-byte uncompressed format.
func SerializeUncompressed(p *Point) []byte {
	result := make([]byte, UncompressedPubKeyLen)
	result[0] = PrefixUncompressed

	xBytes := p.X.Bytes()
	yBytes := p.Y.Bytes()

	copy(result[33-len(xBytes):33], xBytes)
	copy(result[65-len(yBytes):65], yBytes)

	return result
}

// PrivateKeyToPublicKey derives the public key from a private key.
func PrivateKeyToPublicKey(privateKey []byte) *Point {
	return ScalarBaseMult(privateKey)
}

// PrivateKeyToCompressedPublicKey derives the compressed public key from a private key.
func PrivateKeyToCompressedPublicKey(privateKey []byte) []byte {
	point := ScalarBaseMult(privateKey)
	return CompressPoint(point)
}
