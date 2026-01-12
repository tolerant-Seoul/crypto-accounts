package address

import (
	"encoding/hex"
	"strings"
	"testing"
)

// TestTezosAddress tests Tezos (XTZ) address generation
func TestTezosAddress(t *testing.T) {
	tezos := NewTezosAddress()

	// Ed25519 public key (32 bytes)
	pubKeyHex := "a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed"
	pubKey, _ := hex.DecodeString(pubKeyHex)

	// Generate tz1 address
	addr, err := tezos.GenerateTz1(pubKey)
	if err != nil {
		t.Fatalf("GenerateTz1() error = %v", err)
	}

	// tz1 addresses start with "tz1"
	if !strings.HasPrefix(addr, "tz1") {
		t.Errorf("Address should start with tz1, got %s", addr[:3])
	}

	// Tezos addresses are 36 characters
	if len(addr) != 36 {
		t.Errorf("Address length = %d, want 36", len(addr))
	}

	// Validate
	if !tezos.Validate(addr) {
		t.Error("Address validation failed")
	}

	// Test invalid address
	if tezos.Validate("invalid") {
		t.Error("Should reject invalid address")
	}

	// Test GetAddressType
	addrType, err := tezos.GetAddressType(addr)
	if err != nil {
		t.Fatalf("GetAddressType() error = %v", err)
	}
	if addrType != "Ed25519" {
		t.Errorf("GetAddressType() = %s, want Ed25519", addrType)
	}
}

func TestTezosAddressSecp256k1(t *testing.T) {
	tezos := NewTezosAddressWithKeyType(TezosKeySecp256k1)

	// Compressed secp256k1 public key (33 bytes)
	pubKeyHex := "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
	pubKey, _ := hex.DecodeString(pubKeyHex)

	// Generate tz2 address
	addr, err := tezos.GenerateTz2(pubKey)
	if err != nil {
		t.Fatalf("GenerateTz2() error = %v", err)
	}

	// tz2 addresses start with "tz2"
	if !strings.HasPrefix(addr, "tz2") {
		t.Errorf("Address should start with tz2, got %s", addr[:3])
	}

	if !tezos.Validate(addr) {
		t.Error("Address validation failed")
	}
}

// TestZcashAddress tests Zcash (ZEC) transparent address generation
func TestZcashAddress(t *testing.T) {
	zcash := NewZcashAddress()

	// Compressed public key (33 bytes)
	pubKeyHex := "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
	pubKey, _ := hex.DecodeString(pubKeyHex)

	// Generate t1 address
	addr, err := zcash.P2PKH(pubKey)
	if err != nil {
		t.Fatalf("P2PKH() error = %v", err)
	}

	// Zcash transparent addresses start with 't'
	if addr[0] != 't' {
		t.Errorf("Address should start with t, got %c", addr[0])
	}

	// Validate
	if !zcash.Validate(addr) {
		t.Error("Address validation failed")
	}

	// Test GetAddressType
	addrType, err := zcash.GetAddressType(addr)
	if err != nil {
		t.Fatalf("GetAddressType() error = %v", err)
	}
	if addrType != "P2PKH (t1)" {
		t.Errorf("GetAddressType() = %s, want P2PKH (t1)", addrType)
	}

	// Test invalid address
	if zcash.Validate("invalid") {
		t.Error("Should reject invalid address")
	}
}

// TestKaspaAddress tests Kaspa (KAS) address generation
func TestKaspaAddress(t *testing.T) {
	kaspa := NewKaspaAddress()

	// Compressed public key (33 bytes)
	pubKeyHex := "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
	pubKey, _ := hex.DecodeString(pubKeyHex)

	// Generate address
	addr, err := kaspa.Generate(pubKey)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	// Kaspa addresses start with "kaspa1" (Bech32 format)
	if !strings.HasPrefix(addr, "kaspa1") {
		t.Errorf("Address should start with kaspa1, got %s", addr)
	}

	// Validate
	if !kaspa.Validate(addr) {
		t.Error("Address validation failed")
	}

	// Test GetAddressType
	addrType, err := kaspa.GetAddressType(addr)
	if err != nil {
		t.Fatalf("GetAddressType() error = %v", err)
	}
	if !strings.Contains(addrType, "P2PK") {
		t.Errorf("GetAddressType() = %s, want P2PK type", addrType)
	}

	// Test invalid address
	if kaspa.Validate("invalid") {
		t.Error("Should reject invalid address")
	}
}

// TestStacksAddress tests Stacks (STX) address generation
func TestStacksAddress(t *testing.T) {
	stacks := NewStacksAddress()

	// Compressed public key (33 bytes)
	pubKeyHex := "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
	pubKey, _ := hex.DecodeString(pubKeyHex)

	// Generate address
	addr, err := stacks.Generate(pubKey)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	// Stacks addresses start with "S"
	if addr[0] != 'S' {
		t.Errorf("Address should start with S, got %c", addr[0])
	}

	// Validate
	if !stacks.Validate(addr) {
		t.Error("Address validation failed")
	}

	// Test GetAddressType
	addrType, err := stacks.GetAddressType(addr)
	if err != nil {
		t.Fatalf("GetAddressType() error = %v", err)
	}
	if !strings.Contains(addrType, "Mainnet") {
		t.Errorf("GetAddressType() = %s, want Mainnet type", addrType)
	}

	// Test invalid address
	if stacks.Validate("invalid") {
		t.Error("Should reject invalid address")
	}
}

// TestFilecoinAddress tests Filecoin (FIL) address generation
func TestFilecoinAddress(t *testing.T) {
	filecoin := NewFilecoinAddress()

	// Uncompressed public key (65 bytes)
	pubKeyHex := "04" +
		"79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798" +
		"483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"
	pubKey, _ := hex.DecodeString(pubKeyHex)

	// Generate f1 address
	addr, err := filecoin.F1Address(pubKey)
	if err != nil {
		t.Fatalf("F1Address() error = %v", err)
	}

	// Filecoin f1 addresses start with "f1"
	if !strings.HasPrefix(addr, "f1") {
		t.Errorf("Address should start with f1, got %s", addr[:2])
	}

	// Validate
	if !filecoin.Validate(addr) {
		t.Error("Address validation failed")
	}

	// Test GetAddressType
	addrType, err := filecoin.GetAddressType(addr)
	if err != nil {
		t.Fatalf("GetAddressType() error = %v", err)
	}
	if !strings.Contains(addrType, "Secp256k1") {
		t.Errorf("GetAddressType() = %s, want Secp256k1 type", addrType)
	}

	// Test invalid address
	if filecoin.Validate("invalid") {
		t.Error("Should reject invalid address")
	}
}

// TestHederaAddress tests Hedera (HBAR) address generation
func TestHederaAddress(t *testing.T) {
	hedera := NewHederaAddress()

	// Ed25519 public key (32 bytes)
	pubKeyHex := "a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed"
	pubKey, _ := hex.DecodeString(pubKeyHex)

	// Generate alias address
	addr, err := hedera.Generate(pubKey)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	// Hedera addresses are in shard.realm.account format
	if !strings.Contains(addr, ".") {
		t.Errorf("Address should contain '.', got %s", addr)
	}

	// Should start with "0.0."
	if !strings.HasPrefix(addr, "0.0.") {
		t.Errorf("Address should start with 0.0., got %s", addr)
	}

	// Validate
	if !hedera.Validate(addr) {
		t.Error("Address validation failed")
	}

	// Test account ID generation
	accountID := hedera.GenerateAccountID(12345)
	if accountID != "0.0.12345" {
		t.Errorf("GenerateAccountID() = %s, want 0.0.12345", accountID)
	}

	// Test GetAddressType
	addrType, err := hedera.GetAddressType(addr)
	if err != nil {
		t.Fatalf("GetAddressType() error = %v", err)
	}
	if !strings.Contains(addrType, "Alias") {
		t.Errorf("GetAddressType() = %s, want Alias type", addrType)
	}

	// Test invalid address
	if hedera.Validate("invalid") {
		t.Error("Should reject invalid address")
	}
}

// TestICPAddress tests Internet Computer (ICP) Principal ID generation
func TestICPAddress(t *testing.T) {
	icp := NewICPAddress()

	// Ed25519 public key (32 bytes)
	pubKeyHex := "a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed"
	pubKey, _ := hex.DecodeString(pubKeyHex)

	// Generate Principal ID
	addr, err := icp.Generate(pubKey)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	// ICP Principal IDs contain dashes
	if !strings.Contains(addr, "-") {
		t.Errorf("Principal ID should contain dashes, got %s", addr)
	}

	// Validate
	if !icp.Validate(addr) {
		t.Error("Principal ID validation failed")
	}

	// Test GetAddressType
	addrType, err := icp.GetAddressType(addr)
	if err != nil {
		t.Fatalf("GetAddressType() error = %v", err)
	}
	if !strings.Contains(addrType, "Self-Authenticating") {
		t.Errorf("GetAddressType() = %s, want Self-Authenticating type", addrType)
	}

	// Test invalid address
	if icp.Validate("invalid") {
		t.Error("Should reject invalid address")
	}
}

// TestEOSAddress tests EOS address/public key generation
func TestEOSAddress(t *testing.T) {
	eos := NewEOSAddress()

	// Compressed public key (33 bytes)
	pubKeyHex := "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
	pubKey, _ := hex.DecodeString(pubKeyHex)

	// Generate EOS public key
	addr, err := eos.Generate(pubKey)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	// EOS public keys start with "EOS"
	if !strings.HasPrefix(addr, "EOS") {
		t.Errorf("Address should start with EOS, got %s", addr[:3])
	}

	// Validate
	if !eos.Validate(addr) {
		t.Error("EOS public key validation failed")
	}

	// Test PUB_K1 format
	pubK1Addr, err := eos.GeneratePubK1Key(pubKey)
	if err != nil {
		t.Fatalf("GeneratePubK1Key() error = %v", err)
	}
	if !strings.HasPrefix(pubK1Addr, "PUB_K1_") {
		t.Errorf("Address should start with PUB_K1_, got %s", pubK1Addr[:7])
	}
	if !eos.Validate(pubK1Addr) {
		t.Error("PUB_K1 key validation failed")
	}

	// Test account name validation
	if !eos.ValidateAccountName("eosio") {
		t.Error("Should accept valid account name 'eosio'")
	}
	if !eos.ValidateAccountName("myaccount123") {
		t.Error("Should accept valid account name 'myaccount123'")
	}
	if eos.ValidateAccountName("InvalidName") {
		t.Error("Should reject uppercase account name")
	}
	if eos.ValidateAccountName("toolongaccountname") {
		t.Error("Should reject account name longer than 12 chars")
	}

	// Test GetAddressType
	addrType, err := eos.GetAddressType(addr)
	if err != nil {
		t.Fatalf("GetAddressType() error = %v", err)
	}
	if !strings.Contains(addrType, "Legacy") {
		t.Errorf("GetAddressType() = %s, want Legacy type", addrType)
	}
}

// TestFlowAddress tests Flow (FLOW) address generation
func TestFlowAddress(t *testing.T) {
	flow := NewFlowAddress()

	// Compressed public key (33 bytes)
	pubKeyHex := "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
	pubKey, _ := hex.DecodeString(pubKeyHex)

	// Generate address
	addr, err := flow.Generate(pubKey)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	// Flow addresses start with "0x"
	if !strings.HasPrefix(addr, "0x") {
		t.Errorf("Address should start with 0x, got %s", addr[:2])
	}

	// Flow addresses are 18 characters (0x + 16 hex chars)
	if len(addr) != 18 {
		t.Errorf("Address length = %d, want 18", len(addr))
	}

	// Validate
	if !flow.Validate(addr) {
		t.Error("Address validation failed")
	}

	// Test GenerateFromIndex
	indexAddr := flow.GenerateFromIndex(1)
	if indexAddr != "0x0000000000000001" {
		t.Errorf("GenerateFromIndex(1) = %s, want 0x0000000000000001", indexAddr)
	}

	// Test invalid address (all zeros)
	if flow.Validate("0x0000000000000000") {
		t.Error("Should reject all-zero address")
	}

	// Test invalid address
	if flow.Validate("invalid") {
		t.Error("Should reject invalid address")
	}
}

// TestArweaveAddress tests Arweave (AR) address generation
func TestArweaveAddress(t *testing.T) {
	arweave := NewArweaveAddress()

	// RSA public key modulus (256 bytes for 2048-bit RSA)
	// Using a dummy 256-byte key for testing
	pubKey := make([]byte, 256)
	for i := range pubKey {
		pubKey[i] = byte(i)
	}

	// Generate address
	addr, err := arweave.Generate(pubKey)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	// Arweave addresses are 43 characters (Base64URL of SHA-256)
	if len(addr) != 43 {
		t.Errorf("Address length = %d, want 43", len(addr))
	}

	// Validate
	if !arweave.Validate(addr) {
		t.Error("Address validation failed")
	}

	// Test GetAddressType
	addrType, err := arweave.GetAddressType(addr)
	if err != nil {
		t.Fatalf("GetAddressType() error = %v", err)
	}
	if !strings.Contains(addrType, "RSA") {
		t.Errorf("GetAddressType() = %s, want RSA type", addrType)
	}

	// Test invalid address (wrong length)
	if arweave.Validate("tooshort") {
		t.Error("Should reject address with wrong length")
	}

	// Test invalid address
	if arweave.Validate("invalid!@#$%^&*()") {
		t.Error("Should reject invalid address with special chars")
	}
}

// TestMoneroAddress tests Monero (XMR) address generation
func TestMoneroAddress(t *testing.T) {
	monero := NewMoneroAddress()

	// Monero uses dual keys: spend key + view key (each 32 bytes)
	spendKeyHex := "a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed"
	viewKeyHex := "ce5e3294aa964334c284d29d498bb3eb5595214ed3b0c96afee36547a938349c"
	spendKey, _ := hex.DecodeString(spendKeyHex)
	viewKey, _ := hex.DecodeString(viewKeyHex)

	// Generate standard address
	addr, err := monero.GenerateStandard(spendKey, viewKey)
	if err != nil {
		t.Fatalf("GenerateStandard() error = %v", err)
	}

	// Monero standard addresses are 95 characters
	if len(addr) != 95 {
		t.Errorf("Address length = %d, want 95", len(addr))
	}

	// Mainnet standard addresses start with '4'
	if addr[0] != '4' {
		t.Errorf("Address should start with 4, got %c", addr[0])
	}

	// Validate
	if !monero.Validate(addr) {
		t.Error("Address validation failed")
	}

	// Test Generate with combined keys
	combinedKey := append(spendKey, viewKey...)
	addr2, err := monero.Generate(combinedKey)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	if addr != addr2 {
		t.Error("Generate() and GenerateStandard() should produce same address")
	}

	// Test subaddress generation
	subAddr, err := monero.GenerateSubaddress(spendKey, viewKey)
	if err != nil {
		t.Fatalf("GenerateSubaddress() error = %v", err)
	}
	// Mainnet subaddresses start with '8'
	if subAddr[0] != '8' {
		t.Errorf("Subaddress should start with 8, got %c", subAddr[0])
	}
	if !monero.Validate(subAddr) {
		t.Error("Subaddress validation failed")
	}

	// Test GetAddressType
	addrType, err := monero.GetAddressType(addr)
	if err != nil {
		t.Fatalf("GetAddressType() error = %v", err)
	}
	if !strings.Contains(addrType, "Mainnet Standard") {
		t.Errorf("GetAddressType() = %s, want Mainnet Standard", addrType)
	}

	// Test invalid address
	if monero.Validate("invalid") {
		t.Error("Should reject invalid address")
	}
}

// TestNewChainsFactory tests that all new chains are registered in the factory
func TestNewChainsFactory(t *testing.T) {
	factory := NewFactory()

	chains := []ChainID{
		ChainTezos,
		ChainZcash,
		ChainKaspa,
		ChainStacks,
		ChainFilecoin,
		ChainHedera,
		ChainICP,
		ChainEOS,
		ChainFlow,
		ChainArweave,
		ChainMonero,
	}

	for _, chainID := range chains {
		gen, err := factory.Get(chainID)
		if err != nil {
			t.Errorf("Factory.Get(%s) error = %v", chainID, err)
			continue
		}
		if gen == nil {
			t.Errorf("Factory.Get(%s) returned nil", chainID)
		}
	}
}
