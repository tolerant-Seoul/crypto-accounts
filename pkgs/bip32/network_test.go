package bip32

import (
	"testing"
)

func TestMainNetConfiguration(t *testing.T) {
	if MainNet == nil {
		t.Fatal("MainNet is nil")
	}

	if MainNet.Name != "mainnet" {
		t.Errorf("MainNet.Name = %s, want mainnet", MainNet.Name)
	}

	if MainNet.PrivateKeyID != 0x0488ADE4 {
		t.Errorf("MainNet.PrivateKeyID = %x, want 0x0488ADE4", MainNet.PrivateKeyID)
	}

	if MainNet.PublicKeyID != 0x0488B21E {
		t.Errorf("MainNet.PublicKeyID = %x, want 0x0488B21E", MainNet.PublicKeyID)
	}

	if MainNet.PrivateKeyHRP != "xprv" {
		t.Errorf("MainNet.PrivateKeyHRP = %s, want xprv", MainNet.PrivateKeyHRP)
	}

	if MainNet.PublicKeyHRP != "xpub" {
		t.Errorf("MainNet.PublicKeyHRP = %s, want xpub", MainNet.PublicKeyHRP)
	}
}

func TestTestNetConfiguration(t *testing.T) {
	if TestNet == nil {
		t.Fatal("TestNet is nil")
	}

	if TestNet.Name != "testnet" {
		t.Errorf("TestNet.Name = %s, want testnet", TestNet.Name)
	}

	if TestNet.PrivateKeyID != 0x04358394 {
		t.Errorf("TestNet.PrivateKeyID = %x, want 0x04358394", TestNet.PrivateKeyID)
	}

	if TestNet.PublicKeyID != 0x043587CF {
		t.Errorf("TestNet.PublicKeyID = %x, want 0x043587CF", TestNet.PublicKeyID)
	}

	if TestNet.PrivateKeyHRP != "tprv" {
		t.Errorf("TestNet.PrivateKeyHRP = %s, want tprv", TestNet.PrivateKeyHRP)
	}

	if TestNet.PublicKeyHRP != "tpub" {
		t.Errorf("TestNet.PublicKeyHRP = %s, want tpub", TestNet.PublicKeyHRP)
	}
}

func TestDefaultNetwork(t *testing.T) {
	if DefaultNetwork == nil {
		t.Fatal("DefaultNetwork is nil")
	}

	if DefaultNetwork != MainNet {
		t.Error("DefaultNetwork should be MainNet")
	}
}

func TestNetworkFromVersion(t *testing.T) {
	tests := []struct {
		name     string
		version  uint32
		expected *Network
	}{
		{
			name:     "mainnet private",
			version:  0x0488ADE4,
			expected: MainNet,
		},
		{
			name:     "mainnet public",
			version:  0x0488B21E,
			expected: MainNet,
		},
		{
			name:     "testnet private",
			version:  0x04358394,
			expected: TestNet,
		},
		{
			name:     "testnet public",
			version:  0x043587CF,
			expected: TestNet,
		},
		{
			name:     "unknown version",
			version:  0x12345678,
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NetworkFromVersion(tt.version)
			if result != tt.expected {
				t.Errorf("NetworkFromVersion(%x) = %v, want %v", tt.version, result, tt.expected)
			}
		})
	}
}

func TestIsPrivateVersion(t *testing.T) {
	tests := []struct {
		name     string
		version  uint32
		expected bool
	}{
		{
			name:     "mainnet private",
			version:  0x0488ADE4,
			expected: true,
		},
		{
			name:     "mainnet public",
			version:  0x0488B21E,
			expected: false,
		},
		{
			name:     "testnet private",
			version:  0x04358394,
			expected: true,
		},
		{
			name:     "testnet public",
			version:  0x043587CF,
			expected: false,
		},
		{
			name:     "unknown version",
			version:  0x12345678,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsPrivateVersion(tt.version)
			if result != tt.expected {
				t.Errorf("IsPrivateVersion(%x) = %v, want %v", tt.version, result, tt.expected)
			}
		})
	}
}

func TestGetPublicVersion(t *testing.T) {
	tests := []struct {
		name     string
		private  uint32
		expected uint32
	}{
		{
			name:     "mainnet private to public",
			private:  0x0488ADE4,
			expected: 0x0488B21E,
		},
		{
			name:     "testnet private to public",
			private:  0x04358394,
			expected: 0x043587CF,
		},
		{
			name:     "unknown version returns same",
			private:  0x12345678,
			expected: 0x12345678,
		},
		{
			name:     "public version returns same",
			private:  0x0488B21E,
			expected: 0x0488B21E,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetPublicVersion(tt.private)
			if result != tt.expected {
				t.Errorf("GetPublicVersion(%x) = %x, want %x", tt.private, result, tt.expected)
			}
		})
	}
}

func TestNewMasterKeyWithNetwork(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}

	tests := []struct {
		name    string
		network *Network
	}{
		{
			name:    "mainnet",
			network: MainNet,
		},
		{
			name:    "testnet",
			network: TestNet,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := NewMasterKeyWithNetwork(seed, tt.network)
			if err != nil {
				t.Fatalf("NewMasterKeyWithNetwork failed: %v", err)
			}

			if key.Network() != tt.network {
				t.Errorf("Key network = %v, want %v", key.Network(), tt.network)
			}

			// Check version in serialized key
			serialized := key.Serialize()
			version := uint32(serialized[0])<<24 | uint32(serialized[1])<<16 | uint32(serialized[2])<<8 | uint32(serialized[3])

			if version != tt.network.PrivateKeyID {
				t.Errorf("Serialized version = %x, want %x", version, tt.network.PrivateKeyID)
			}
		})
	}
}

func TestNetworkPreservedThroughDerivation(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}

	// Create testnet master key
	master, err := NewMasterKeyWithNetwork(seed, TestNet)
	if err != nil {
		t.Fatalf("NewMasterKeyWithNetwork failed: %v", err)
	}

	// Derive child
	child, err := master.Child(0)
	if err != nil {
		t.Fatalf("Child derivation failed: %v", err)
	}

	// Check network is preserved
	childKey := child.(*ExtendedKey)
	if childKey.Network() != TestNet {
		t.Error("Network not preserved through derivation")
	}

	// Check in serialized form - should start with tprv
	serialized := child.String()
	if serialized[:4] != "tprv" {
		t.Errorf("Child key prefix = %s, want tprv", serialized[:4])
	}

	// Neuter and check
	pub, _ := child.Neuter()
	pubSerialized := pub.String()
	if pubSerialized[:4] != "tpub" {
		t.Errorf("Neutered key prefix = %s, want tpub", pubSerialized[:4])
	}
}
