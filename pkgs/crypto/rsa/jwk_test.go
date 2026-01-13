package rsa

import (
	"testing"
)

func TestPrivateKeyToJWK(t *testing.T) {
	key, err := GenerateKey(KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	jwk := PrivateKeyToJWK(key)

	if jwk.Kty != "RSA" {
		t.Errorf("Expected kty 'RSA', got '%s'", jwk.Kty)
	}
	if jwk.N == "" {
		t.Error("JWK N (modulus) is empty")
	}
	if jwk.E == "" {
		t.Error("JWK E (exponent) is empty")
	}
	if jwk.D == "" {
		t.Error("JWK D (private exponent) is empty")
	}
	if jwk.P == "" {
		t.Error("JWK P (prime) is empty")
	}
	if jwk.Q == "" {
		t.Error("JWK Q (prime) is empty")
	}
}

func TestPublicKeyToJWK(t *testing.T) {
	key, err := GenerateKey(KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	jwk := PublicKeyToJWK(&key.PublicKey)

	if jwk.Kty != "RSA" {
		t.Errorf("Expected kty 'RSA', got '%s'", jwk.Kty)
	}
	if jwk.N == "" {
		t.Error("JWK N (modulus) is empty")
	}
	if jwk.E == "" {
		t.Error("JWK E (exponent) is empty")
	}
	// Public key JWK should not have private components
	if jwk.D != "" {
		t.Error("Public key JWK should not have D")
	}
}

func TestJWKRoundTrip(t *testing.T) {
	// Generate original key
	originalKey, err := GenerateKey(KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Convert to JWK
	jwk := PrivateKeyToJWK(originalKey)

	// Convert to JSON
	jsonStr, err := jwk.ToJSON()
	if err != nil {
		t.Fatalf("Failed to convert to JSON: %v", err)
	}

	// Parse JSON back to JWK
	parsedJWK, err := JWKFromJSON(jsonStr)
	if err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}

	// Convert back to private key
	restoredKey, err := parsedJWK.ToPrivateKey()
	if err != nil {
		t.Fatalf("Failed to convert JWK to private key: %v", err)
	}

	// Verify keys match
	if originalKey.N.Cmp(restoredKey.N) != 0 {
		t.Error("Restored key N doesn't match original")
	}
	if originalKey.E != restoredKey.E {
		t.Error("Restored key E doesn't match original")
	}
	if originalKey.D.Cmp(restoredKey.D) != 0 {
		t.Error("Restored key D doesn't match original")
	}
}

func TestPrivateKeyFromJWKJSON(t *testing.T) {
	// Generate a key and get its JWK JSON
	key, err := GenerateKey(KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	jwk := PrivateKeyToJWK(key)
	jsonStr, _ := jwk.ToJSON()

	// Parse directly from JSON
	restored, err := PrivateKeyFromJWKJSON(jsonStr)
	if err != nil {
		t.Fatalf("Failed to parse key from JWK JSON: %v", err)
	}

	if key.N.Cmp(restored.N) != 0 {
		t.Error("Restored key N doesn't match original")
	}
}

func TestGetArweaveOwner(t *testing.T) {
	key, err := GenerateKey(KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	owner := GetArweaveOwner(&key.PublicKey)
	if owner == "" {
		t.Error("GetArweaveOwner returned empty string")
	}

	// Owner should be Base64URL encoded
	// For 2048-bit key, modulus is 256 bytes
	// Base64 of 256 bytes = ceil(256 * 4/3) = 342 characters
	if len(owner) < 340 {
		t.Errorf("Owner seems too short: %d characters", len(owner))
	}
}

func TestJWKInvalidJSON(t *testing.T) {
	_, err := JWKFromJSON("not valid json")
	if err == nil {
		t.Error("Expected error for invalid JSON")
	}
}

func TestJWKInvalidKeyType(t *testing.T) {
	jwk := &JWK{
		Kty: "EC", // Wrong type
		N:   "test",
		E:   "AQAB",
	}

	_, err := jwk.ToPublicKey()
	if err == nil {
		t.Error("Expected error for wrong key type")
	}
}
