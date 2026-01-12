package address

import (
	"encoding/hex"
	"testing"
)

// Test vectors from known sources
// Bitcoin test vector from BIP-32/BIP-44
func TestBitcoinAddress(t *testing.T) {
	btc := NewBitcoinAddress(false)

	// Compressed public key (33 bytes)
	pubKeyHex := "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
	pubKey, _ := hex.DecodeString(pubKeyHex)

	// P2PKH address
	addr, err := btc.P2PKH(pubKey)
	if err != nil {
		t.Fatalf("P2PKH() error = %v", err)
	}

	// This is the known P2PKH address for this public key
	expectedP2PKH := "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"
	if addr != expectedP2PKH {
		t.Errorf("P2PKH() = %s, want %s", addr, expectedP2PKH)
	}

	// P2WPKH (Bech32) address
	bech32Addr, err := btc.P2WPKH(pubKey)
	if err != nil {
		t.Fatalf("P2WPKH() error = %v", err)
	}

	// Verify it starts with bc1q
	if bech32Addr[:4] != "bc1q" {
		t.Errorf("P2WPKH() should start with bc1q, got %s", bech32Addr[:4])
	}

	// Validate P2PKH address
	if !btc.Validate(addr) {
		t.Error("P2PKH address validation failed")
	}

	// Bech32 address starts with bc1
	if bech32Addr[:3] != "bc1" {
		t.Error("Bech32 address should start with bc1")
	}
}

func TestEthereumAddress(t *testing.T) {
	eth := NewEthereumAddress()

	// Uncompressed public key (64 bytes, without 04 prefix)
	// Test vector from known Ethereum address generation
	pubKeyHex := "9166c289b9f905e55f9e3df9f69d7f356b4a22095f894f4715714aa4b56606af" +
		"01f656ec2cfbe0db1e1f9ba96ccef69bb6b25e5a9c69aa027d730fde5e8efb01"
	pubKey, _ := hex.DecodeString(pubKeyHex)

	addr, err := eth.Generate(pubKey)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	// Verify format
	if len(addr) != 42 {
		t.Errorf("Address length = %d, want 42", len(addr))
	}
	if addr[:2] != "0x" {
		t.Error("Address should start with 0x")
	}

	// Validate
	if !eth.Validate(addr) {
		t.Error("Address validation failed")
	}

	// Test invalid address
	if eth.Validate("invalid") {
		t.Error("Should reject invalid address")
	}
}

func TestLitecoinAddress(t *testing.T) {
	ltc := NewLitecoinAddress(false)

	pubKeyHex := "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
	pubKey, _ := hex.DecodeString(pubKeyHex)

	addr, err := ltc.P2PKH(pubKey)
	if err != nil {
		t.Fatalf("P2PKH() error = %v", err)
	}

	// Litecoin P2PKH addresses start with L
	if addr[0] != 'L' {
		t.Errorf("Address should start with L, got %c", addr[0])
	}

	if !ltc.Validate(addr) {
		t.Error("Address validation failed")
	}
}

func TestDogecoinAddress(t *testing.T) {
	doge := NewDogecoinAddress(false)

	pubKeyHex := "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
	pubKey, _ := hex.DecodeString(pubKeyHex)

	addr, err := doge.P2PKH(pubKey)
	if err != nil {
		t.Fatalf("P2PKH() error = %v", err)
	}

	// Dogecoin P2PKH addresses start with D
	if addr[0] != 'D' {
		t.Errorf("Address should start with D, got %c", addr[0])
	}

	if !doge.Validate(addr) {
		t.Error("Address validation failed")
	}
}

func TestTronAddress(t *testing.T) {
	tron := NewTronAddress(false)

	// Uncompressed public key (64 bytes)
	pubKeyHex := "9166c289b9f905e55f9e3df9f69d7f356b4a22095f894f4715714aa4b56606af" +
		"01f656ec2cfbe0db1e1f9ba96ccef69bb6b25e5a9c69aa027d730fde5e8efb01"
	pubKey, _ := hex.DecodeString(pubKeyHex)

	addr, err := tron.Generate(pubKey)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	// TRON addresses start with T
	if addr[0] != 'T' {
		t.Errorf("Address should start with T, got %c", addr[0])
	}

	if !tron.Validate(addr) {
		t.Error("Address validation failed")
	}

	// Test hex address generation
	hexAddr, err := tron.GenerateHex(pubKey)
	if err != nil {
		t.Fatalf("GenerateHex() error = %v", err)
	}

	if hexAddr[:2] != "41" {
		t.Error("Hex address should start with 41")
	}
}

func TestSolanaAddress(t *testing.T) {
	sol := NewSolanaAddress()

	// 32-byte Ed25519 public key
	pubKeyHex := "0000000000000000000000000000000000000000000000000000000000000001"
	pubKey, _ := hex.DecodeString(pubKeyHex)

	addr, err := sol.Generate(pubKey)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if !sol.Validate(addr) {
		t.Error("Address validation failed")
	}

	// Decode and verify
	info, err := sol.DecodeAddress(addr)
	if err != nil {
		t.Fatalf("DecodeAddress() error = %v", err)
	}

	if hex.EncodeToString(info.PublicKey) != pubKeyHex {
		t.Error("Decoded public key doesn't match")
	}
}

func TestStellarAddress(t *testing.T) {
	stellar := NewStellarAddress()

	// 32-byte Ed25519 public key
	pubKeyHex := "0000000000000000000000000000000000000000000000000000000000000001"
	pubKey, _ := hex.DecodeString(pubKeyHex)

	addr, err := stellar.Generate(pubKey)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	// Stellar addresses start with G
	if addr[0] != 'G' {
		t.Errorf("Address should start with G, got %c", addr[0])
	}

	// Should be 56 characters
	if len(addr) != 56 {
		t.Errorf("Address length = %d, want 56", len(addr))
	}

	if !stellar.Validate(addr) {
		t.Error("Address validation failed")
	}
}

func TestRippleAddress(t *testing.T) {
	xrp := NewRippleAddress()

	// Compressed public key
	pubKeyHex := "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
	pubKey, _ := hex.DecodeString(pubKeyHex)

	addr, err := xrp.Generate(pubKey)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	// Ripple addresses start with r
	if addr[0] != 'r' {
		t.Errorf("Address should start with r, got %c", addr[0])
	}

	if !xrp.Validate(addr) {
		t.Error("Address validation failed")
	}
}

func TestCosmosAddress(t *testing.T) {
	cosmos := NewCosmosAddress()

	// Compressed public key
	pubKeyHex := "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
	pubKey, _ := hex.DecodeString(pubKeyHex)

	addr, err := cosmos.Generate(pubKey)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	// Cosmos addresses start with cosmos1
	if addr[:7] != "cosmos1" {
		t.Errorf("Address should start with cosmos1, got %s", addr[:7])
	}

	if !cosmos.Validate(addr) {
		t.Error("Address validation failed")
	}
}

func TestAlgorandAddress(t *testing.T) {
	algo := NewAlgorandAddress()

	// 32-byte Ed25519 public key
	pubKeyHex := "0000000000000000000000000000000000000000000000000000000000000001"
	pubKey, _ := hex.DecodeString(pubKeyHex)

	addr, err := algo.Generate(pubKey)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	// Algorand addresses are 58 characters
	if len(addr) != 58 {
		t.Errorf("Address length = %d, want 58", len(addr))
	}

	if !algo.Validate(addr) {
		t.Error("Address validation failed")
	}
}

func TestPolkadotAddress(t *testing.T) {
	dot := NewPolkadotAddress()

	// 32-byte public key
	pubKeyHex := "0000000000000000000000000000000000000000000000000000000000000001"
	pubKey, _ := hex.DecodeString(pubKeyHex)

	addr, err := dot.Generate(pubKey)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	// Polkadot addresses start with 1
	if addr[0] != '1' {
		t.Errorf("Address should start with 1, got %c", addr[0])
	}

	if !dot.Validate(addr) {
		t.Error("Address validation failed")
	}
}

func TestAptosAddress(t *testing.T) {
	aptos := NewAptosAddress()

	// 32-byte Ed25519 public key
	pubKeyHex := "0000000000000000000000000000000000000000000000000000000000000001"
	pubKey, _ := hex.DecodeString(pubKeyHex)

	addr, err := aptos.Generate(pubKey)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	// Aptos addresses start with 0x
	if addr[:2] != "0x" {
		t.Error("Address should start with 0x")
	}

	// Should be 66 characters (0x + 64 hex chars)
	if len(addr) != 66 {
		t.Errorf("Address length = %d, want 66", len(addr))
	}

	if !aptos.Validate(addr) {
		t.Error("Address validation failed")
	}
}

func TestSuiAddress(t *testing.T) {
	sui := NewSuiAddress()

	// 32-byte Ed25519 public key
	pubKeyHex := "0000000000000000000000000000000000000000000000000000000000000001"
	pubKey, _ := hex.DecodeString(pubKeyHex)

	addr, err := sui.Generate(pubKey)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	// Sui addresses start with 0x
	if addr[:2] != "0x" {
		t.Error("Address should start with 0x")
	}

	// Should be 66 characters (0x + 64 hex chars)
	if len(addr) != 66 {
		t.Errorf("Address length = %d, want 66", len(addr))
	}

	if !sui.Validate(addr) {
		t.Error("Address validation failed")
	}
}

func TestNEARAddress(t *testing.T) {
	near := NewNEARAddress()

	// 32-byte Ed25519 public key
	pubKeyHex := "0000000000000000000000000000000000000000000000000000000000000001"
	pubKey, _ := hex.DecodeString(pubKeyHex)

	addr, err := near.Generate(pubKey)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	// NEAR implicit addresses are 64 hex characters
	if len(addr) != 64 {
		t.Errorf("Address length = %d, want 64", len(addr))
	}

	if !near.ValidateImplicit(addr) {
		t.Error("Implicit address validation failed")
	}

	// Test named address validation
	if !near.ValidateNamed("alice.near") {
		t.Error("Named address 'alice.near' should be valid")
	}

	if !near.ValidateNamed("bob.alice.near") {
		t.Error("Named address 'bob.alice.near' should be valid")
	}

	if near.ValidateNamed("-invalid") {
		t.Error("Named address '-invalid' should be invalid")
	}
}

func TestBitcoinCashAddress(t *testing.T) {
	bch := NewBitcoinCashAddress(false)

	// Compressed public key
	pubKeyHex := "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
	pubKey, _ := hex.DecodeString(pubKeyHex)

	addr, err := bch.Generate(pubKey)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	// Bitcoin Cash addresses start with bitcoincash:q
	if addr[:13] != "bitcoincash:q" {
		t.Errorf("Address should start with bitcoincash:q, got %s", addr[:13])
	}

	// Test that the address was generated
	if len(addr) < 42 {
		t.Error("Address too short")
	}
}

func TestFactory(t *testing.T) {
	factory := NewFactory()

	// Test listing supported chains
	chains := factory.ListSupportedChains()
	if len(chains) == 0 {
		t.Error("Factory should have supported chains")
	}

	// Test getting a generator
	btcGen, err := factory.Get(ChainBitcoin)
	if err != nil {
		t.Fatalf("Get(ChainBitcoin) error = %v", err)
	}

	if btcGen.ChainID() != ChainBitcoin {
		t.Error("Generator ChainID mismatch")
	}

	// Test unsupported chain
	_, err = factory.Get("unsupported")
	if err == nil {
		t.Error("Should return error for unsupported chain")
	}
}

func TestBase58Encoding(t *testing.T) {
	tests := []struct {
		input    []byte
		expected string
	}{
		{[]byte{0}, "1"},
		{[]byte{0, 0, 0, 1}, "1112"},
		{[]byte{97, 98, 99}, "ZiCa"},
	}

	for _, tt := range tests {
		result := Base58Encode(tt.input)
		if result != tt.expected {
			t.Errorf("Base58Encode(%v) = %s, want %s", tt.input, result, tt.expected)
		}

		// Test round-trip
		decoded, err := Base58Decode(result)
		if err != nil {
			t.Errorf("Base58Decode(%s) error = %v", result, err)
		}
		if hex.EncodeToString(decoded) != hex.EncodeToString(tt.input) {
			t.Errorf("Base58Decode round-trip failed: got %v, want %v", decoded, tt.input)
		}
	}
}

func TestBech32Encoding(t *testing.T) {
	// Test vector from BIP-173
	hrp := "bc"
	data := []byte{0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94, 0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6}

	// Encode
	encoded, err := SegWitEncode(hrp, 0, data)
	if err != nil {
		t.Fatalf("SegWitEncode() error = %v", err)
	}

	// Should start with bc1q (version 0)
	if encoded[:4] != "bc1q" {
		t.Errorf("Encoded address should start with bc1q, got %s", encoded[:4])
	}

	// Known BIP-173 test vector address
	// For this pubkeyhash, the expected address is bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4
	expectedAddr := "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
	if encoded != expectedAddr {
		t.Errorf("Encoded address = %s, want %s", encoded, expectedAddr)
	}
}

func TestHash160(t *testing.T) {
	// Test vector
	input, _ := hex.DecodeString("0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")
	expected := "751e76e8199196d454941c45d1b3a323f1433bd6"

	result := Hash160(input)
	if hex.EncodeToString(result) != expected {
		t.Errorf("Hash160() = %s, want %s", hex.EncodeToString(result), expected)
	}
}

func TestKeccak256(t *testing.T) {
	// Test vector: Keccak256("") = c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
	input := []byte{}
	expected := "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"

	result := Keccak256(input)
	if hex.EncodeToString(result) != expected {
		t.Errorf("Keccak256() = %s, want %s", hex.EncodeToString(result), expected)
	}
}
