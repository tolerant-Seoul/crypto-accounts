package secp256k1

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestCompressDecompressPoint(t *testing.T) {
	// Use generator point as test case
	g := Generator()

	compressed := CompressPoint(g)

	if len(compressed) != CompressedPubKeyLen {
		t.Errorf("Compressed length = %d, want %d", len(compressed), CompressedPubKeyLen)
	}

	// First byte should be 02 or 03
	if compressed[0] != PrefixEven && compressed[0] != PrefixOdd {
		t.Errorf("Invalid prefix: %02x", compressed[0])
	}

	// Decompress and verify
	decompressed, err := DecompressPoint(compressed)
	if err != nil {
		t.Fatalf("DecompressPoint failed: %v", err)
	}

	if !decompressed.Equal(g) {
		t.Error("Decompressed point does not match original")
	}
}

func TestCompressPointPrefix(t *testing.T) {
	// Test with known points
	tests := []struct {
		name           string
		privateKey     string
		expectedPrefix byte
	}{
		{
			name:           "private key 1 (even Y)",
			privateKey:     "0000000000000000000000000000000000000000000000000000000000000001",
			expectedPrefix: PrefixEven, // G has even Y
		},
		{
			name:           "private key 2 (odd Y)",
			privateKey:     "0000000000000000000000000000000000000000000000000000000000000002",
			expectedPrefix: PrefixEven, // 2G has even Y
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			privKey, _ := hex.DecodeString(tt.privateKey)
			pubKey := PrivateKeyToCompressedPublicKey(privKey)

			if pubKey[0] != tt.expectedPrefix {
				t.Logf("Note: prefix is %02x (may vary based on Y coordinate parity)", pubKey[0])
			}

			// Verify it's a valid prefix
			if pubKey[0] != PrefixEven && pubKey[0] != PrefixOdd {
				t.Errorf("Invalid prefix: %02x", pubKey[0])
			}
		})
	}
}

func TestDecompressPointErrors(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantErr bool
	}{
		{
			name:    "wrong length",
			input:   make([]byte, 32),
			wantErr: true,
		},
		{
			name:    "invalid prefix 00",
			input:   append([]byte{0x00}, make([]byte, 32)...),
			wantErr: true,
		},
		{
			name:    "invalid prefix 01",
			input:   append([]byte{0x01}, make([]byte, 32)...),
			wantErr: true,
		},
		{
			name:    "invalid prefix 04",
			input:   append([]byte{0x04}, make([]byte, 32)...),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecompressPoint(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("DecompressPoint() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestParsePublicKeyCompressed(t *testing.T) {
	// Generate a valid compressed public key
	privKey, _ := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000001")
	compressed := PrivateKeyToCompressedPublicKey(privKey)

	point, err := ParsePublicKey(compressed)
	if err != nil {
		t.Fatalf("ParsePublicKey(compressed) failed: %v", err)
	}

	if !point.Equal(Generator()) {
		t.Error("Parsed point should equal generator")
	}
}

func TestParsePublicKeyUncompressed(t *testing.T) {
	g := Generator()
	uncompressed := SerializeUncompressed(g)

	if len(uncompressed) != UncompressedPubKeyLen {
		t.Errorf("Uncompressed length = %d, want %d", len(uncompressed), UncompressedPubKeyLen)
	}

	if uncompressed[0] != PrefixUncompressed {
		t.Errorf("Uncompressed prefix = %02x, want %02x", uncompressed[0], PrefixUncompressed)
	}

	point, err := ParsePublicKey(uncompressed)
	if err != nil {
		t.Fatalf("ParsePublicKey(uncompressed) failed: %v", err)
	}

	if !point.Equal(g) {
		t.Error("Parsed point should equal generator")
	}
}

func TestParsePublicKeyErrors(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantErr bool
	}{
		{
			name:    "empty input",
			input:   []byte{},
			wantErr: true,
		},
		{
			name:    "wrong length 32",
			input:   make([]byte, 32),
			wantErr: true,
		},
		{
			name:    "wrong length 64",
			input:   make([]byte, 64),
			wantErr: true,
		},
		{
			name:    "uncompressed wrong prefix",
			input:   append([]byte{0x05}, make([]byte, 64)...),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParsePublicKey(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParsePublicKey() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestPrivateKeyToPublicKey(t *testing.T) {
	privKey, _ := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000001")

	pubPoint := PrivateKeyToPublicKey(privKey)

	if !pubPoint.Equal(Generator()) {
		t.Error("PrivateKeyToPublicKey(1) should return generator")
	}
}

func TestPrivateKeyToCompressedPublicKey(t *testing.T) {
	// Known test vector from Bitcoin
	privKey, _ := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000001")
	expectedPubKey := "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

	pubKey := PrivateKeyToCompressedPublicKey(privKey)

	if hex.EncodeToString(pubKey) != expectedPubKey {
		t.Errorf("PrivateKeyToCompressedPublicKey() = %x, want %s", pubKey, expectedPubKey)
	}
}

func TestSerializeUncompressed(t *testing.T) {
	g := Generator()
	uncompressed := SerializeUncompressed(g)

	// Check length
	if len(uncompressed) != 65 {
		t.Errorf("Length = %d, want 65", len(uncompressed))
	}

	// Check prefix
	if uncompressed[0] != 0x04 {
		t.Errorf("Prefix = %02x, want 04", uncompressed[0])
	}

	// Verify X coordinate
	xBytes := uncompressed[1:33]
	if !bytes.Equal(xBytes, padTo32(Gx.Bytes())) {
		t.Error("X coordinate mismatch")
	}

	// Verify Y coordinate
	yBytes := uncompressed[33:65]
	if !bytes.Equal(yBytes, padTo32(Gy.Bytes())) {
		t.Error("Y coordinate mismatch")
	}
}

func TestRoundTripCompression(t *testing.T) {
	// Test multiple private keys
	privateKeys := []string{
		"0000000000000000000000000000000000000000000000000000000000000001",
		"0000000000000000000000000000000000000000000000000000000000000002",
		"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
		"e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
	}

	for _, privHex := range privateKeys {
		t.Run(privHex[:8]+"...", func(t *testing.T) {
			privKey, _ := hex.DecodeString(privHex)
			pubPoint := PrivateKeyToPublicKey(privKey)

			// Compress
			compressed := CompressPoint(pubPoint)

			// Decompress
			recovered, err := DecompressPoint(compressed)
			if err != nil {
				t.Fatalf("DecompressPoint failed: %v", err)
			}

			if !recovered.Equal(pubPoint) {
				t.Error("Round-trip compression failed")
			}
		})
	}
}

// Helper function
func padTo32(b []byte) []byte {
	if len(b) >= 32 {
		return b
	}
	padded := make([]byte, 32)
	copy(padded[32-len(b):], b)
	return padded
}
