package rsa

import (
	"crypto/rsa"
	"testing"
)

func TestGenerateKey(t *testing.T) {
	// Test 2048-bit key generation
	key2048, err := GenerateKey(KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate 2048-bit key: %v", err)
	}
	if key2048.N.BitLen() != 2048 {
		t.Errorf("Expected 2048-bit key, got %d bits", key2048.N.BitLen())
	}
}

func TestGenerateArweaveKey(t *testing.T) {
	key, err := GenerateArweaveKey()
	if err != nil {
		t.Fatalf("Failed to generate Arweave key: %v", err)
	}
	if key.N.BitLen() != 4096 {
		t.Errorf("Expected 4096-bit key, got %d bits", key.N.BitLen())
	}
}

func TestPrivateKeyToFromBytes(t *testing.T) {
	// Generate a test key
	key, err := GenerateKey(KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Convert to bytes
	bytes := PrivateKeyToBytes(key)
	if len(bytes) == 0 {
		t.Fatal("PrivateKeyToBytes returned empty bytes")
	}

	// Convert back
	restored, err := PrivateKeyFromBytes(bytes)
	if err != nil {
		t.Fatalf("Failed to restore key from bytes: %v", err)
	}

	// Verify keys match
	if key.N.Cmp(restored.N) != 0 {
		t.Error("Restored key N doesn't match original")
	}
	if key.E != restored.E {
		t.Error("Restored key E doesn't match original")
	}
}

func TestPrivateKeyPEM(t *testing.T) {
	// Generate a test key
	key, err := GenerateKey(KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Convert to PEM
	pem := PrivateKeyToPEM(key)
	if len(pem) == 0 {
		t.Fatal("PrivateKeyToPEM returned empty data")
	}

	// Convert back
	restored, err := PrivateKeyFromPEM(pem)
	if err != nil {
		t.Fatalf("Failed to restore key from PEM: %v", err)
	}

	// Verify keys match
	if key.N.Cmp(restored.N) != 0 {
		t.Error("Restored key N doesn't match original")
	}
}

func TestPublicKeyToBytes(t *testing.T) {
	key, err := GenerateKey(KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	modulus := PublicKeyToBytes(&key.PublicKey)
	if len(modulus) == 0 {
		t.Error("PublicKeyToBytes returned empty bytes")
	}

	// 2048 bits = 256 bytes
	if len(modulus) != 256 {
		t.Errorf("Expected 256-byte modulus for 2048-bit key, got %d bytes", len(modulus))
	}
}

func TestArweaveAddressHash(t *testing.T) {
	key, err := GenerateKey(KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	modulus := GetModulus(&key.PublicKey)
	hash := ArweaveAddressHash(modulus)

	// SHA-256 produces 32 bytes
	if len(hash) != 32 {
		t.Errorf("Expected 32-byte hash, got %d bytes", len(hash))
	}
}

func TestValidateKeySize(t *testing.T) {
	// Test with valid key
	key4096, _ := GenerateKey(KeySize4096)
	if err := ValidateKeySize(&key4096.PublicKey); err != nil {
		t.Errorf("4096-bit key should be valid: %v", err)
	}

	// Test with valid key
	key2048, _ := GenerateKey(KeySize2048)
	if err := ValidateKeySize(&key2048.PublicKey); err != nil {
		t.Errorf("2048-bit key should be valid: %v", err)
	}

	// Test with small key (manually create)
	smallKey := &rsa.PublicKey{N: key2048.N.Rsh(key2048.N, 1024), E: 65537}
	if err := ValidateKeySize(smallKey); err == nil {
		t.Error("Small key should fail validation")
	}
}

func TestGetKeyInfo(t *testing.T) {
	key, err := GenerateKey(KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	info := GetKeyInfo(&key.PublicKey)
	if info.BitSize != 2048 {
		t.Errorf("Expected BitSize 2048, got %d", info.BitSize)
	}
	if info.Exponent != 65537 {
		t.Errorf("Expected exponent 65537, got %d", info.Exponent)
	}
	if len(info.Modulus) != 256 {
		t.Errorf("Expected 256-byte modulus, got %d bytes", len(info.Modulus))
	}
}
