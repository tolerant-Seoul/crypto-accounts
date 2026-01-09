package encoding

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestBase58Encode(t *testing.T) {
	tests := []struct {
		name     string
		input    string // hex encoded
		expected string
	}{
		{
			name:     "empty",
			input:    "",
			expected: "",
		},
		{
			name:     "single zero byte",
			input:    "00",
			expected: "1",
		},
		{
			name:     "multiple leading zeros",
			input:    "000000",
			expected: "111",
		},
		{
			name:     "hello world hex",
			input:    "48656c6c6f20576f726c64",
			expected: "JxF12TrwUP45BMd",
		},
		{
			name:     "Bitcoin address payload",
			input:    "00010966776006953d5567439e5e39f86a0d273beed61967f6",
			expected: "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input, _ := hex.DecodeString(tt.input)
			result := Base58Encode(input)

			if result != tt.expected {
				t.Errorf("Base58Encode() = %s, want %s", result, tt.expected)
			}
		})
	}
}

func TestBase58Decode(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string // hex encoded
		wantErr  bool
	}{
		{
			name:     "empty",
			input:    "",
			expected: "",
			wantErr:  false,
		},
		{
			name:     "single 1",
			input:    "1",
			expected: "00",
			wantErr:  false,
		},
		{
			name:     "multiple 1s",
			input:    "111",
			expected: "000000",
			wantErr:  false,
		},
		{
			name:     "hello world",
			input:    "JxF12TrwUP45BMd",
			expected: "48656c6c6f20576f726c64",
			wantErr:  false,
		},
		{
			name:     "Bitcoin address",
			input:    "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM",
			expected: "00010966776006953d5567439e5e39f86a0d273beed61967f6",
			wantErr:  false,
		},
		{
			name:     "invalid character 0",
			input:    "0InvalidChar",
			wantErr:  true,
		},
		{
			name:     "invalid character O",
			input:    "OInvalidChar",
			wantErr:  true,
		},
		{
			name:     "invalid character I",
			input:    "IInvalidChar",
			wantErr:  true,
		},
		{
			name:     "invalid character l",
			input:    "lInvalidChar",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := Base58Decode(tt.input)

			if (err != nil) != tt.wantErr {
				t.Errorf("Base58Decode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				expected, _ := hex.DecodeString(tt.expected)
				if !bytes.Equal(result, expected) {
					t.Errorf("Base58Decode() = %x, want %s", result, tt.expected)
				}
			}
		})
	}
}

func TestBase58RoundTrip(t *testing.T) {
	testCases := [][]byte{
		{},
		{0x00},
		{0x00, 0x00, 0x00},
		{0x01, 0x02, 0x03},
		{0xff, 0xfe, 0xfd},
		make([]byte, 100),
	}

	// Add some random-like data
	for i := range testCases[len(testCases)-1] {
		testCases[len(testCases)-1][i] = byte(i * 17)
	}

	for i, original := range testCases {
		encoded := Base58Encode(original)
		decoded, err := Base58Decode(encoded)

		if err != nil {
			t.Errorf("Case %d: Base58Decode failed: %v", i, err)
			continue
		}

		if !bytes.Equal(decoded, original) {
			t.Errorf("Case %d: Round-trip failed. Original: %x, Got: %x", i, original, decoded)
		}
	}
}

func TestBase58CheckEncode(t *testing.T) {
	tests := []struct {
		name     string
		input    string // hex encoded
		expected string
	}{
		{
			name:     "Bitcoin address version 0",
			input:    "00010966776006953d5567439e5e39f86a0d273bee",
			expected: "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM",
		},
		{
			name:     "empty payload with version",
			input:    "00",
			expected: "1Wh4bh",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input, _ := hex.DecodeString(tt.input)
			result := Base58CheckEncode(input)

			if result != tt.expected {
				t.Errorf("Base58CheckEncode() = %s, want %s", result, tt.expected)
			}
		})
	}
}

func TestBase58CheckDecode(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string // hex encoded
		wantErr  bool
	}{
		{
			name:     "valid Bitcoin address",
			input:    "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM",
			expected: "00010966776006953d5567439e5e39f86a0d273bee",
			wantErr:  false,
		},
		{
			name:     "valid empty payload",
			input:    "1Wh4bh",
			expected: "00",
			wantErr:  false,
		},
		{
			name:    "invalid checksum",
			input:   "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvN", // changed last char
			wantErr: true,
		},
		{
			name:    "too short",
			input:   "1",
			wantErr: true,
		},
		{
			name:    "invalid base58 character",
			input:   "0InvalidBase58",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := Base58CheckDecode(tt.input)

			if (err != nil) != tt.wantErr {
				t.Errorf("Base58CheckDecode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				expected, _ := hex.DecodeString(tt.expected)
				if !bytes.Equal(result, expected) {
					t.Errorf("Base58CheckDecode() = %x, want %s", result, tt.expected)
				}
			}
		})
	}
}

func TestBase58CheckRoundTrip(t *testing.T) {
	testCases := [][]byte{
		{0x00},                               // Version byte only
		{0x00, 0x01, 0x02, 0x03},             // Short payload
		{0x05, 0xaa, 0xbb, 0xcc, 0xdd, 0xee}, // P2SH-like
	}

	// Add a typical address payload
	addressPayload := make([]byte, 21) // Version + 20-byte hash
	addressPayload[0] = 0x00
	for i := 1; i < 21; i++ {
		addressPayload[i] = byte(i)
	}
	testCases = append(testCases, addressPayload)

	for i, original := range testCases {
		encoded := Base58CheckEncode(original)
		decoded, err := Base58CheckDecode(encoded)

		if err != nil {
			t.Errorf("Case %d: Base58CheckDecode failed: %v", i, err)
			continue
		}

		if !bytes.Equal(decoded, original) {
			t.Errorf("Case %d: Round-trip failed. Original: %x, Got: %x", i, original, decoded)
		}
	}
}

func TestBase58CheckDecodeErrors(t *testing.T) {
	tests := []struct {
		name  string
		input string
		err   error
	}{
		{
			name:  "invalid base58",
			input: "0Invalid",
			err:   ErrInvalidBase58,
		},
		{
			name:  "too short for checksum",
			input: "1",
			err:   ErrInvalidDataLength,
		},
		{
			name:  "wrong checksum",
			input: "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvN",
			err:   ErrInvalidChecksum,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Base58CheckDecode(tt.input)
			if err == nil {
				t.Error("Expected error, got nil")
			}
		})
	}
}

func TestLeadingZeroPreservation(t *testing.T) {
	// Leading zeros should be preserved in Base58 encoding
	testCases := []struct {
		zeros int
	}{
		{1},
		{2},
		{5},
		{10},
	}

	for _, tc := range testCases {
		data := make([]byte, tc.zeros+5)
		// Leave leading bytes as zero, fill rest with non-zero
		for i := tc.zeros; i < len(data); i++ {
			data[i] = byte(i)
		}

		encoded := Base58Encode(data)
		decoded, err := Base58Decode(encoded)

		if err != nil {
			t.Errorf("Failed to decode with %d leading zeros: %v", tc.zeros, err)
			continue
		}

		if !bytes.Equal(decoded, data) {
			t.Errorf("Leading zeros not preserved. Want %d zeros, got data: %x", tc.zeros, decoded)
		}

		// Count leading '1's in encoded string
		leadingOnes := 0
		for _, c := range encoded {
			if c != '1' {
				break
			}
			leadingOnes++
		}

		if leadingOnes != tc.zeros {
			t.Errorf("Expected %d leading '1's, got %d", tc.zeros, leadingOnes)
		}
	}
}
