package secp256k1

import (
	"encoding/hex"
	"math/big"
	"testing"
)

func TestCurveParameters(t *testing.T) {
	// Verify curve parameters are properly initialized
	if N == nil || N.Sign() == 0 {
		t.Error("Curve order N is not initialized")
	}
	if P == nil || P.Sign() == 0 {
		t.Error("Field prime P is not initialized")
	}
	if Gx == nil || Gx.Sign() == 0 {
		t.Error("Generator X coordinate is not initialized")
	}
	if Gy == nil || Gy.Sign() == 0 {
		t.Error("Generator Y coordinate is not initialized")
	}

	// Verify N < P (curve order is less than field prime)
	if N.Cmp(P) >= 0 {
		t.Error("Curve order N should be less than field prime P")
	}
}

func TestGenerator(t *testing.T) {
	g := Generator()

	if g.X.Cmp(Gx) != 0 {
		t.Error("Generator X coordinate mismatch")
	}
	if g.Y.Cmp(Gy) != 0 {
		t.Error("Generator Y coordinate mismatch")
	}
}

func TestInfinity(t *testing.T) {
	inf := Infinity()

	if !inf.IsInfinity() {
		t.Error("Infinity point should be at infinity")
	}

	if inf.X.Sign() != 0 || inf.Y.Sign() != 0 {
		t.Error("Infinity point should have zero coordinates")
	}
}

func TestPointClone(t *testing.T) {
	p := Generator()
	clone := p.Clone()

	// Verify values are equal
	if !p.Equal(clone) {
		t.Error("Clone should be equal to original")
	}

	// Verify they are different objects
	clone.X.SetInt64(0)
	if p.X.Cmp(Gx) != 0 {
		t.Error("Modifying clone should not affect original")
	}
}

func TestPointEqual(t *testing.T) {
	p1 := Generator()
	p2 := Generator()
	p3 := &Point{X: big.NewInt(1), Y: big.NewInt(2)}

	if !p1.Equal(p2) {
		t.Error("Same points should be equal")
	}

	if p1.Equal(p3) {
		t.Error("Different points should not be equal")
	}
}

func TestAddWithInfinity(t *testing.T) {
	g := Generator()
	inf := Infinity()

	// G + O = G
	result := Add(g, inf)
	if !result.Equal(g) {
		t.Error("G + O should equal G")
	}

	// O + G = G
	result = Add(inf, g)
	if !result.Equal(g) {
		t.Error("O + G should equal G")
	}

	// O + O = O
	result = Add(inf, inf)
	if !result.IsInfinity() {
		t.Error("O + O should equal O")
	}
}

func TestDouble(t *testing.T) {
	g := Generator()

	// 2G should not be infinity
	twoG := Double(g)
	if twoG.IsInfinity() {
		t.Error("2G should not be at infinity")
	}

	// 2G should be different from G
	if twoG.Equal(g) {
		t.Error("2G should be different from G")
	}

	// Verify 2G = G + G
	sumG := Add(g, g)
	if !twoG.Equal(sumG) {
		t.Error("2G should equal G + G")
	}
}

func TestScalarMult(t *testing.T) {
	g := Generator()

	// 1 * G = G
	oneG := ScalarMult(g, big.NewInt(1))
	if !oneG.Equal(g) {
		t.Error("1 * G should equal G")
	}

	// 2 * G = 2G
	twoG := ScalarMult(g, big.NewInt(2))
	expected := Double(g)
	if !twoG.Equal(expected) {
		t.Error("2 * G should equal Double(G)")
	}

	// 3 * G = 2G + G
	threeG := ScalarMult(g, big.NewInt(3))
	expected = Add(twoG, g)
	if !threeG.Equal(expected) {
		t.Error("3 * G should equal 2G + G")
	}

	// 0 * G = O (infinity)
	zeroG := ScalarMult(g, big.NewInt(0))
	if !zeroG.IsInfinity() {
		t.Error("0 * G should be at infinity")
	}
}

func TestScalarBaseMult(t *testing.T) {
	// Known test vector
	privKey, _ := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000001")
	result := ScalarBaseMult(privKey)

	// 1 * G = G
	if !result.Equal(Generator()) {
		t.Error("ScalarBaseMult(1) should equal G")
	}
}

func TestIsValidPrivateKey(t *testing.T) {
	tests := []struct {
		name  string
		key   []byte
		valid bool
	}{
		{
			name:  "valid key",
			key:   hexToBytes("0000000000000000000000000000000000000000000000000000000000000001"),
			valid: true,
		},
		{
			name:  "another valid key",
			key:   hexToBytes("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140"),
			valid: true,
		},
		{
			name:  "zero key",
			key:   hexToBytes("0000000000000000000000000000000000000000000000000000000000000000"),
			valid: false,
		},
		{
			name:  "key equal to N",
			key:   hexToBytes("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"),
			valid: false,
		},
		{
			name:  "key greater than N",
			key:   hexToBytes("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364142"),
			valid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsValidPrivateKey(tt.key)
			if result != tt.valid {
				t.Errorf("IsValidPrivateKey() = %v, want %v", result, tt.valid)
			}
		})
	}
}

func TestAddPrivateKeys(t *testing.T) {
	k1 := hexToBytes("0000000000000000000000000000000000000000000000000000000000000001")
	k2 := hexToBytes("0000000000000000000000000000000000000000000000000000000000000002")

	result := AddPrivateKeys(k1, k2)

	expected := hexToBytes("0000000000000000000000000000000000000000000000000000000000000003")
	if hex.EncodeToString(result) != hex.EncodeToString(expected) {
		t.Errorf("AddPrivateKeys() = %x, want %x", result, expected)
	}

	// Result should be 32 bytes
	if len(result) != 32 {
		t.Errorf("AddPrivateKeys() result length = %d, want 32", len(result))
	}
}

func TestAddPrivateKeysModN(t *testing.T) {
	// Test wraparound: (N-1) + 2 = 1 (mod N)
	nMinus1 := hexToBytes("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140")
	two := hexToBytes("0000000000000000000000000000000000000000000000000000000000000002")

	result := AddPrivateKeys(nMinus1, two)

	expected := hexToBytes("0000000000000000000000000000000000000000000000000000000000000001")
	if hex.EncodeToString(result) != hex.EncodeToString(expected) {
		t.Errorf("AddPrivateKeys() with wraparound = %x, want %x", result, expected)
	}
}

// Helper function
func hexToBytes(s string) []byte {
	b, _ := hex.DecodeString(s)
	return b
}
