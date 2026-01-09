// Package secp256k1 provides elliptic curve operations for the secp256k1 curve.
// This curve is used by Bitcoin, Ethereum, and many other cryptocurrencies.
package secp256k1

import (
	"math/big"
)

// Curve parameters for secp256k1
var (
	// N is the order of the curve (number of points on the curve)
	N, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)

	// P is the prime field of the curve
	P, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)

	// Gx is the x-coordinate of the generator point
	Gx, _ = new(big.Int).SetString("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16)

	// Gy is the y-coordinate of the generator point
	Gy, _ = new(big.Int).SetString("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)
)

// Point represents a point on the secp256k1 elliptic curve.
type Point struct {
	X, Y *big.Int
}

// Generator returns the generator point G of the secp256k1 curve.
func Generator() *Point {
	return &Point{
		X: new(big.Int).Set(Gx),
		Y: new(big.Int).Set(Gy),
	}
}

// Infinity returns the point at infinity (identity element).
func Infinity() *Point {
	return &Point{
		X: big.NewInt(0),
		Y: big.NewInt(0),
	}
}

// IsInfinity returns true if the point is the point at infinity.
func (p *Point) IsInfinity() bool {
	return p.X.Sign() == 0 && p.Y.Sign() == 0
}

// Clone returns a deep copy of the point.
func (p *Point) Clone() *Point {
	return &Point{
		X: new(big.Int).Set(p.X),
		Y: new(big.Int).Set(p.Y),
	}
}

// Equal returns true if two points are equal.
func (p *Point) Equal(other *Point) bool {
	return p.X.Cmp(other.X) == 0 && p.Y.Cmp(other.Y) == 0
}

// Add performs point addition: P1 + P2.
func Add(p1, p2 *Point) *Point {
	if p1.IsInfinity() {
		return p2.Clone()
	}
	if p2.IsInfinity() {
		return p1.Clone()
	}

	if p1.X.Cmp(p2.X) == 0 {
		if p1.Y.Cmp(p2.Y) == 0 {
			return Double(p1)
		}
		return Infinity()
	}

	// lambda = (y2 - y1) / (x2 - x1) mod P
	dy := new(big.Int).Sub(p2.Y, p1.Y)
	dx := new(big.Int).Sub(p2.X, p1.X)
	dxInv := new(big.Int).ModInverse(dx, P)
	lambda := new(big.Int).Mul(dy, dxInv)
	lambda.Mod(lambda, P)

	// x3 = lambda^2 - x1 - x2 mod P
	x3 := new(big.Int).Mul(lambda, lambda)
	x3.Sub(x3, p1.X)
	x3.Sub(x3, p2.X)
	x3.Mod(x3, P)

	// y3 = lambda * (x1 - x3) - y1 mod P
	y3 := new(big.Int).Sub(p1.X, x3)
	y3.Mul(y3, lambda)
	y3.Sub(y3, p1.Y)
	y3.Mod(y3, P)

	return &Point{X: x3, Y: y3}
}

// Double performs point doubling: 2P.
func Double(p *Point) *Point {
	if p.Y.Sign() == 0 {
		return Infinity()
	}

	// lambda = (3 * x^2) / (2 * y) mod P (a = 0 for secp256k1)
	x2 := new(big.Int).Mul(p.X, p.X)
	x2.Mod(x2, P)
	numerator := new(big.Int).Mul(x2, big.NewInt(3))

	denominator := new(big.Int).Mul(p.Y, big.NewInt(2))
	denomInv := new(big.Int).ModInverse(denominator, P)

	lambda := new(big.Int).Mul(numerator, denomInv)
	lambda.Mod(lambda, P)

	// x3 = lambda^2 - 2*x mod P
	x3 := new(big.Int).Mul(lambda, lambda)
	x3.Sub(x3, new(big.Int).Mul(p.X, big.NewInt(2)))
	x3.Mod(x3, P)

	// y3 = lambda * (x - x3) - y mod P
	y3 := new(big.Int).Sub(p.X, x3)
	y3.Mul(y3, lambda)
	y3.Sub(y3, p.Y)
	y3.Mod(y3, P)

	return &Point{X: x3, Y: y3}
}

// ScalarMult performs scalar multiplication: k * P using double-and-add algorithm.
func ScalarMult(p *Point, k *big.Int) *Point {
	result := Infinity()
	addend := p.Clone()

	for i := 0; i < k.BitLen(); i++ {
		if k.Bit(i) == 1 {
			result = Add(result, addend)
		}
		addend = Double(addend)
	}

	return result
}

// ScalarBaseMult performs scalar multiplication with the generator point: k * G.
func ScalarBaseMult(k []byte) *Point {
	scalar := new(big.Int).SetBytes(k)
	return ScalarMult(Generator(), scalar)
}

// IsValidPrivateKey checks if a byte slice is a valid private key.
func IsValidPrivateKey(key []byte) bool {
	k := new(big.Int).SetBytes(key)
	return k.Sign() > 0 && k.Cmp(N) < 0
}

// AddPrivateKeys adds two private keys modulo N.
func AddPrivateKeys(k1, k2 []byte) []byte {
	key1 := new(big.Int).SetBytes(k1)
	key2 := new(big.Int).SetBytes(k2)

	result := new(big.Int).Add(key1, key2)
	result.Mod(result, N)

	// Pad to 32 bytes
	resultBytes := result.Bytes()
	padded := make([]byte, 32)
	copy(padded[32-len(resultBytes):], resultBytes)

	return padded
}
