package address

import (
	"fmt"
)

// SolanaAddress generates Solana addresses
// Solana uses Ed25519 public keys directly as addresses, encoded in Base58
type SolanaAddress struct{}

// NewSolanaAddress creates a new Solana address generator
func NewSolanaAddress() *SolanaAddress {
	return &SolanaAddress{}
}

// ChainID returns the chain identifier
func (s *SolanaAddress) ChainID() ChainID {
	return ChainSolana
}

// Generate creates a Solana address from a public key
// Public key should be 32 bytes (Ed25519 public key)
func (s *SolanaAddress) Generate(publicKey []byte) (string, error) {
	if len(publicKey) != 32 {
		return "", fmt.Errorf("Solana requires 32-byte Ed25519 public key, got %d bytes", len(publicKey))
	}

	// Solana addresses are simply Base58-encoded public keys
	return Base58Encode(publicKey), nil
}

// Validate checks if a Solana address is valid
func (s *SolanaAddress) Validate(address string) bool {
	decoded, err := Base58Decode(address)
	if err != nil {
		return false
	}

	// Solana addresses are 32 bytes
	return len(decoded) == 32
}

// DecodeAddress decodes a Solana address
func (s *SolanaAddress) DecodeAddress(address string) (*AddressInfo, error) {
	decoded, err := Base58Decode(address)
	if err != nil {
		return nil, err
	}

	if len(decoded) != 32 {
		return nil, fmt.Errorf("invalid Solana address length: expected 32, got %d", len(decoded))
	}

	return &AddressInfo{
		Address:   address,
		PublicKey: decoded,
		ChainID:   ChainSolana,
		Type:      AddressTypeBase58,
	}, nil
}

// DeriveAssociatedTokenAddress derives an associated token account address
// This is a Program Derived Address (PDA)
func (s *SolanaAddress) DeriveAssociatedTokenAddress(walletAddress, tokenMintAddress string) (string, error) {
	// Note: This would require proper PDA derivation with seeds
	// For now, this is a placeholder showing the concept
	return "", fmt.Errorf("PDA derivation requires additional implementation")
}
