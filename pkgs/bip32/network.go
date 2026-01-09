package bip32

// Network represents the version bytes for different cryptocurrency networks.
// This allows extending to different networks without modifying existing code (OCP).
type Network struct {
	Name           string
	PrivateKeyID   uint32 // Version bytes for private extended keys
	PublicKeyID    uint32 // Version bytes for public extended keys
	PrivateKeyHRP  string // Human-readable prefix for private keys (e.g., "xprv")
	PublicKeyHRP   string // Human-readable prefix for public keys (e.g., "xpub")
}

// Predefined networks
var (
	// MainNet is the Bitcoin mainnet network configuration.
	MainNet = &Network{
		Name:          "mainnet",
		PrivateKeyID:  0x0488ADE4, // xprv
		PublicKeyID:   0x0488B21E, // xpub
		PrivateKeyHRP: "xprv",
		PublicKeyHRP:  "xpub",
	}

	// TestNet is the Bitcoin testnet network configuration.
	TestNet = &Network{
		Name:          "testnet",
		PrivateKeyID:  0x04358394, // tprv
		PublicKeyID:   0x043587CF, // tpub
		PrivateKeyHRP: "tprv",
		PublicKeyHRP:  "tpub",
	}

	// DefaultNetwork is the default network used for key generation.
	DefaultNetwork = MainNet
)

// NetworkFromVersion returns the Network for a given version byte.
func NetworkFromVersion(version uint32) *Network {
	switch version {
	case MainNet.PrivateKeyID, MainNet.PublicKeyID:
		return MainNet
	case TestNet.PrivateKeyID, TestNet.PublicKeyID:
		return TestNet
	default:
		return nil
	}
}

// IsPrivateVersion returns true if the version indicates a private key.
func IsPrivateVersion(version uint32) bool {
	return version == MainNet.PrivateKeyID || version == TestNet.PrivateKeyID
}

// GetPublicVersion returns the public version for a given private version.
func GetPublicVersion(privateVersion uint32) uint32 {
	switch privateVersion {
	case MainNet.PrivateKeyID:
		return MainNet.PublicKeyID
	case TestNet.PrivateKeyID:
		return TestNet.PublicKeyID
	default:
		return privateVersion
	}
}
