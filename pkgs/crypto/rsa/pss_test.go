package rsa

import (
	"testing"
)

func TestPSSSignAndVerify(t *testing.T) {
	// Generate a test key
	key, err := GenerateKey(KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	pss := NewPSS(key)

	// Test data
	data := []byte("Hello, Arweave!")

	// Sign
	signature, err := pss.Sign(data)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	// Verify
	if !pss.Verify(data, signature) {
		t.Error("Signature verification failed")
	}

	// Verify with wrong data should fail
	wrongData := []byte("Wrong data")
	if pss.Verify(wrongData, signature) {
		t.Error("Verification should fail with wrong data")
	}
}

func TestSignWithKey(t *testing.T) {
	key, err := GenerateKey(KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	data := []byte("Test message")
	signature, err := SignWithKey(key, data)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	// Verify
	if !VerifyPSS(&key.PublicKey, data, signature) {
		t.Error("Signature verification failed")
	}
}

func TestArweaveSignatureSize(t *testing.T) {
	key2048, _ := GenerateKey(KeySize2048)
	key4096, _ := GenerateKey(KeySize4096)

	size2048 := ArweaveSignatureSize(&key2048.PublicKey)
	size4096 := ArweaveSignatureSize(&key4096.PublicKey)

	// 2048 bits = 256 bytes signature
	if size2048 != 256 {
		t.Errorf("Expected 256-byte signature for 2048-bit key, got %d", size2048)
	}

	// 4096 bits = 512 bytes signature
	if size4096 != 512 {
		t.Errorf("Expected 512-byte signature for 4096-bit key, got %d", size4096)
	}
}

func TestPSSNilKey(t *testing.T) {
	pss := NewPSS(nil)
	_, err := pss.Sign([]byte("test"))
	if err == nil {
		t.Error("Expected error when signing with nil key")
	}
}
