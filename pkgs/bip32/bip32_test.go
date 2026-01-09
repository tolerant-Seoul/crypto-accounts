package bip32

import (
	"encoding/hex"
	"testing"
)

// Test vectors from BIP-32 specification
// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#test-vectors

func TestVector1(t *testing.T) {
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")

	master, err := NewMasterKey(seed)
	if err != nil {
		t.Fatalf("Failed to create master key: %v", err)
	}

	// Test chain m
	expectedXprv := "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
	expectedXpub := "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"

	if got := master.String(); got != expectedXprv {
		t.Errorf("Master xprv mismatch:\n  got:  %s\n  want: %s", got, expectedXprv)
	}

	pub, _ := master.Neuter()
	if got := pub.String(); got != expectedXpub {
		t.Errorf("Master xpub mismatch:\n  got:  %s\n  want: %s", got, expectedXpub)
	}

	// Test chain m/0'
	child0h, err := master.Child(Hardened(0))
	if err != nil {
		t.Fatalf("Failed to derive m/0': %v", err)
	}

	expectedXprv0h := "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7"
	expectedXpub0h := "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw"

	if got := child0h.String(); got != expectedXprv0h {
		t.Errorf("m/0' xprv mismatch:\n  got:  %s\n  want: %s", got, expectedXprv0h)
	}

	pub0h, _ := child0h.Neuter()
	if got := pub0h.String(); got != expectedXpub0h {
		t.Errorf("m/0' xpub mismatch:\n  got:  %s\n  want: %s", got, expectedXpub0h)
	}

	// Test chain m/0'/1
	child0h1, err := child0h.(*ExtendedKey).Child(1)
	if err != nil {
		t.Fatalf("Failed to derive m/0'/1: %v", err)
	}

	expectedXprv0h1 := "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs"
	expectedXpub0h1 := "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ"

	if got := child0h1.String(); got != expectedXprv0h1 {
		t.Errorf("m/0'/1 xprv mismatch:\n  got:  %s\n  want: %s", got, expectedXprv0h1)
	}

	pub0h1, _ := child0h1.Neuter()
	if got := pub0h1.String(); got != expectedXpub0h1 {
		t.Errorf("m/0'/1 xpub mismatch:\n  got:  %s\n  want: %s", got, expectedXpub0h1)
	}
}

func TestVector2(t *testing.T) {
	seed, _ := hex.DecodeString("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542")

	master, err := NewMasterKey(seed)
	if err != nil {
		t.Fatalf("Failed to create master key: %v", err)
	}

	expectedXprv := "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U"
	expectedXpub := "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"

	if got := master.String(); got != expectedXprv {
		t.Errorf("Master xprv mismatch:\n  got:  %s\n  want: %s", got, expectedXprv)
	}

	pub, _ := master.Neuter()
	if got := pub.String(); got != expectedXpub {
		t.Errorf("Master xpub mismatch:\n  got:  %s\n  want: %s", got, expectedXpub)
	}

	// Test chain m/0
	child0, err := master.Child(0)
	if err != nil {
		t.Fatalf("Failed to derive m/0: %v", err)
	}

	expectedXprv0 := "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt"
	expectedXpub0 := "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH"

	if got := child0.String(); got != expectedXprv0 {
		t.Errorf("m/0 xprv mismatch:\n  got:  %s\n  want: %s", got, expectedXprv0)
	}

	pub0, _ := child0.Neuter()
	if got := pub0.String(); got != expectedXpub0 {
		t.Errorf("m/0 xpub mismatch:\n  got:  %s\n  want: %s", got, expectedXpub0)
	}
}

func TestDerivationPath(t *testing.T) {
	tests := []struct {
		input    string
		expected string
		indices  []uint32
	}{
		{"m", "m", []uint32{}},
		{"m/0", "m/0", []uint32{0}},
		{"m/0/1", "m/0/1", []uint32{0, 1}},
		{"m/44'/60'/0'/0/0", "m/44'/60'/0'/0/0", []uint32{Hardened(44), Hardened(60), Hardened(0), 0, 0}},
		{"44'/0'/0'", "m/44'/0'/0'", []uint32{Hardened(44), Hardened(0), Hardened(0)}},
		{"m/0h/1h/2", "m/0'/1'/2", []uint32{Hardened(0), Hardened(1), 2}},
	}

	for _, tt := range tests {
		path, err := ParsePath(tt.input)
		if err != nil {
			t.Errorf("ParsePath(%q) error: %v", tt.input, err)
			continue
		}

		if path.String() != tt.expected {
			t.Errorf("ParsePath(%q).String() = %q, want %q", tt.input, path.String(), tt.expected)
		}

		if len(path) != len(tt.indices) {
			t.Errorf("ParsePath(%q) len = %d, want %d", tt.input, len(path), len(tt.indices))
			continue
		}

		for i, idx := range path {
			if idx != tt.indices[i] {
				t.Errorf("ParsePath(%q)[%d] = %d, want %d", tt.input, i, idx, tt.indices[i])
			}
		}
	}
}

func TestDeriveFromPathString(t *testing.T) {
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	master, _ := NewMasterKey(seed)

	child, err := master.DeriveFromPathString("m/0'/1")
	if err != nil {
		t.Fatalf("DeriveFromPathString failed: %v", err)
	}

	expectedXprv := "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs"
	if got := child.String(); got != expectedXprv {
		t.Errorf("DeriveFromPathString(m/0'/1) = %s, want %s", got, expectedXprv)
	}
}

func TestParseExtendedKey(t *testing.T) {
	xprv := "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
	xpub := "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"

	privKey, err := ParseExtendedKey(xprv)
	if err != nil {
		t.Fatalf("ParseExtendedKey(xprv) error: %v", err)
	}
	if !privKey.IsPrivate() {
		t.Error("Expected private key")
	}
	if privKey.String() != xprv {
		t.Errorf("Round-trip xprv failed: got %s", privKey.String())
	}

	pubKey, err := ParseExtendedKey(xpub)
	if err != nil {
		t.Fatalf("ParseExtendedKey(xpub) error: %v", err)
	}
	if pubKey.IsPrivate() {
		t.Error("Expected public key")
	}
	if pubKey.String() != xpub {
		t.Errorf("Round-trip xpub failed: got %s", pubKey.String())
	}
}

func TestPublicKeyDerivation(t *testing.T) {
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	master, _ := NewMasterKey(seed)

	masterPub, _ := master.Neuter()

	// Derive m/0 from both private and public
	childFromPriv, _ := master.Child(0)
	childFromPub, _ := masterPub.(*ExtendedKey).Child(0)

	// Their public keys should match
	privPub, _ := childFromPriv.Neuter()
	if privPub.String() != childFromPub.String() {
		t.Error("Public key derivation mismatch")
	}
}

func TestHardenedDerivationFromPublicKey(t *testing.T) {
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	master, _ := NewMasterKey(seed)
	masterPub, _ := master.Neuter()

	_, err := masterPub.(*ExtendedKey).Child(Hardened(0))
	if err != ErrHardenedFromPublic {
		t.Errorf("Expected ErrHardenedFromPublic, got %v", err)
	}
}

func TestInvalidSeed(t *testing.T) {
	_, err := NewMasterKey([]byte{0x01, 0x02, 0x03})
	if err != ErrInvalidSeedLength {
		t.Errorf("Expected ErrInvalidSeedLength for short seed, got %v", err)
	}

	longSeed := make([]byte, 65)
	_, err = NewMasterKey(longSeed)
	if err != ErrInvalidSeedLength {
		t.Errorf("Expected ErrInvalidSeedLength for long seed, got %v", err)
	}
}

func TestKeyInterface(t *testing.T) {
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	master, _ := NewMasterKey(seed)

	// Test that ExtendedKey implements Key interface
	var key Key = master
	if !key.IsPrivate() {
		t.Error("Master key should be private")
	}

	if key.Depth() != 0 {
		t.Error("Master key depth should be 0")
	}

	if key.ChildIndex() != 0 {
		t.Error("Master key child index should be 0")
	}

	if len(key.ChainCode()) != 32 {
		t.Error("Chain code should be 32 bytes")
	}

	if len(key.PublicKeyBytes()) != 33 {
		t.Error("Public key should be 33 bytes")
	}

	if len(key.PrivateKeyBytes()) != 32 {
		t.Error("Private key should be 32 bytes")
	}
}
