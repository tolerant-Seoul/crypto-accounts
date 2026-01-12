package ed25519

import (
	"encoding/hex"
	"testing"
)

func TestPrivateKeyToPublicKey(t *testing.T) {
	// Test vector from SLIP-10
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")

	// Derive master key
	privateKey, publicKey, err := DeriveKeyFromPath(seed, nil)
	if err != nil {
		t.Fatalf("Failed to derive key: %v", err)
	}

	t.Logf("Private Key: %s", hex.EncodeToString(privateKey))
	t.Logf("Public Key: %s", hex.EncodeToString(publicKey))

	// Verify public key can be derived from private key
	derivedPubKey, err := PrivateKeyToPublicKey(privateKey)
	if err != nil {
		t.Fatalf("Failed to derive public key: %v", err)
	}

	if hex.EncodeToString(derivedPubKey) != hex.EncodeToString(publicKey) {
		t.Errorf("Public key mismatch")
	}
}

func TestSignAndVerify(t *testing.T) {
	privateKey, _ := hex.DecodeString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")

	publicKey, err := PrivateKeyToPublicKey(privateKey)
	if err != nil {
		t.Fatalf("Failed to derive public key: %v", err)
	}

	message := []byte("test message")

	signature, err := Sign(privateKey, message)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	if len(signature) != SignatureSize {
		t.Errorf("Expected signature size %d, got %d", SignatureSize, len(signature))
	}

	if !Verify(publicKey, message, signature) {
		t.Error("Signature verification failed")
	}

	// Test with wrong message
	if Verify(publicKey, []byte("wrong message"), signature) {
		t.Error("Verification should fail with wrong message")
	}
}

func TestSLIP10Derivation(t *testing.T) {
	// SLIP-10 test vector for Ed25519
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")

	// Test m/0'/1'/2'
	path := []uint32{0x80000000, 0x80000001, 0x80000002}

	privateKey, publicKey, err := DeriveKeyFromPath(seed, path)
	if err != nil {
		t.Fatalf("Failed to derive key: %v", err)
	}

	t.Logf("Path m/0'/1'/2'")
	t.Logf("Private Key: %s", hex.EncodeToString(privateKey))
	t.Logf("Public Key: %s", hex.EncodeToString(publicKey))

	if len(privateKey) != PrivateKeySize {
		t.Errorf("Expected private key size %d, got %d", PrivateKeySize, len(privateKey))
	}

	if len(publicKey) != PublicKeySize {
		t.Errorf("Expected public key size %d, got %d", PublicKeySize, len(publicKey))
	}
}

func TestSolanaDerivationPath(t *testing.T) {
	// Solana uses m/44'/501'/0'/0'
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f")

	// m/44'/501'/0'/0' (all hardened)
	path := []uint32{
		0x80000000 + 44,  // 44'
		0x80000000 + 501, // 501' (Solana coin type)
		0x80000000 + 0,   // 0'
		0x80000000 + 0,   // 0'
	}

	privateKey, publicKey, err := DeriveKeyFromPath(seed, path)
	if err != nil {
		t.Fatalf("Failed to derive Solana key: %v", err)
	}

	t.Logf("Solana Path m/44'/501'/0'/0'")
	t.Logf("Private Key: %s", hex.EncodeToString(privateKey))
	t.Logf("Public Key: %s", hex.EncodeToString(publicKey))
}

func TestInvalidInputs(t *testing.T) {
	// Test invalid private key size
	_, err := PrivateKeyToPublicKey([]byte("short"))
	if err != ErrInvalidPrivateKey {
		t.Error("Expected ErrInvalidPrivateKey for short key")
	}

	// Test invalid signature
	if Verify(make([]byte, 32), []byte("msg"), make([]byte, 32)) {
		t.Error("Should fail with invalid signature size")
	}
}
