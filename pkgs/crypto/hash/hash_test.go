package hash

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestSHA256(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "empty string",
			input:    "",
			expected: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			name:     "hello",
			input:    "hello",
			expected: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
		},
		{
			name:     "The quick brown fox",
			input:    "The quick brown fox jumps over the lazy dog",
			expected: "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SHA256([]byte(tt.input))
			expected, _ := hex.DecodeString(tt.expected)

			if !bytes.Equal(result, expected) {
				t.Errorf("SHA256() = %x, want %s", result, tt.expected)
			}
		})
	}
}

func TestDoubleSHA256(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "empty string",
			input:    "",
			expected: "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456",
		},
		{
			name:     "hello",
			input:    "hello",
			expected: "9595c9df90075148eb06860365df33584b75bff782a510c6cd4883a419833d50",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DoubleSHA256([]byte(tt.input))
			expected, _ := hex.DecodeString(tt.expected)

			if !bytes.Equal(result, expected) {
				t.Errorf("DoubleSHA256() = %x, want %s", result, tt.expected)
			}
		})
	}
}

func TestRIPEMD160(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "empty string",
			input:    "",
			expected: "9c1185a5c5e9fc54612808977ee8f548b2258d31",
		},
		{
			name:     "hello",
			input:    "hello",
			expected: "108f07b8382412612c048d07d13f814118445acd",
		},
		{
			name:     "The quick brown fox",
			input:    "The quick brown fox jumps over the lazy dog",
			expected: "37f332f68db77bd9d7edd4969571ad671cf9dd3b",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := RIPEMD160([]byte(tt.input))
			expected, _ := hex.DecodeString(tt.expected)

			if !bytes.Equal(result, expected) {
				t.Errorf("RIPEMD160() = %x, want %s", result, tt.expected)
			}
		})
	}
}

func TestHash160(t *testing.T) {
	// Hash160 = RIPEMD160(SHA256(data))
	// This is commonly used for Bitcoin addresses

	tests := []struct {
		name     string
		input    []byte
		expected string
	}{
		{
			name: "compressed public key",
			// This is the compressed public key for private key = 1
			input:    hexToBytes("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
			expected: "751e76e8199196d454941c45d1b3a323f1433bd6",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Hash160(tt.input)
			expected, _ := hex.DecodeString(tt.expected)

			if !bytes.Equal(result, expected) {
				t.Errorf("Hash160() = %x, want %s", result, tt.expected)
			}

			// Verify length is 20 bytes
			if len(result) != 20 {
				t.Errorf("Hash160() length = %d, want 20", len(result))
			}
		})
	}
}

func TestHMACSHA512(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		data     string
		expected string
	}{
		{
			name:     "Bitcoin seed",
			key:      "Bitcoin seed",
			data:     "000102030405060708090a0b0c0d0e0f",
			expected: "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, _ := hex.DecodeString(tt.data)
			result := HMACSHA512([]byte(tt.key), data)
			expected, _ := hex.DecodeString(tt.expected)

			if !bytes.Equal(result, expected) {
				t.Errorf("HMACSHA512() = %x, want %s", result, tt.expected)
			}

			// Verify length is 64 bytes
			if len(result) != 64 {
				t.Errorf("HMACSHA512() length = %d, want 64", len(result))
			}
		})
	}
}

func TestChecksum(t *testing.T) {
	data := []byte("hello world")
	checksum := Checksum(data)

	if len(checksum) != 4 {
		t.Errorf("Checksum length = %d, want 4", len(checksum))
	}

	// Checksum should be first 4 bytes of DoubleSHA256
	fullHash := DoubleSHA256(data)
	expected := fullHash[:4]

	if !bytes.Equal(checksum, expected) {
		t.Errorf("Checksum() = %x, want %x", checksum, expected)
	}
}

func TestVerifyChecksum(t *testing.T) {
	tests := []struct {
		name   string
		data   []byte
		valid  bool
	}{
		{
			name:  "valid checksum",
			data:  appendChecksum([]byte("hello")),
			valid: true,
		},
		{
			name:  "invalid checksum",
			data:  append([]byte("hello"), 0x00, 0x00, 0x00, 0x00),
			valid: false,
		},
		{
			name:  "too short",
			data:  []byte{0x01, 0x02, 0x03},
			valid: false,
		},
		{
			name:  "empty",
			data:  []byte{},
			valid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := VerifyChecksum(tt.data)
			if result != tt.valid {
				t.Errorf("VerifyChecksum() = %v, want %v", result, tt.valid)
			}
		})
	}
}

func TestVerifyChecksumRoundTrip(t *testing.T) {
	testCases := [][]byte{
		[]byte(""),
		[]byte("a"),
		[]byte("hello world"),
		[]byte("The quick brown fox jumps over the lazy dog"),
		make([]byte, 1000), // Large data
	}

	for i, data := range testCases {
		withChecksum := appendChecksum(data)

		if !VerifyChecksum(withChecksum) {
			t.Errorf("Case %d: VerifyChecksum failed for valid data", i)
		}

		// Corrupt the checksum
		corrupted := make([]byte, len(withChecksum))
		copy(corrupted, withChecksum)
		corrupted[len(corrupted)-1] ^= 0xFF

		if VerifyChecksum(corrupted) {
			t.Errorf("Case %d: VerifyChecksum passed for corrupted data", i)
		}
	}
}

// Helper functions
func hexToBytes(s string) []byte {
	b, _ := hex.DecodeString(s)
	return b
}

func appendChecksum(data []byte) []byte {
	checksum := Checksum(data)
	return append(data, checksum...)
}
