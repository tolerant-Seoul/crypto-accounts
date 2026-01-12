package address

import (
	"fmt"
	"strings"
)

// Avalanche chain HRPs
const (
	AvalancheXChainHRP = "avax"
	AvalanchePChainHRP = "avax"
	AvalancheCChainHRP = "" // C-Chain uses Ethereum addresses
)

// AvalancheAddress generates Avalanche addresses
type AvalancheAddress struct {
	chainType string // "X", "P", or "C"
}

// NewAvalancheXChainAddress creates an X-Chain address generator
func NewAvalancheXChainAddress() *AvalancheAddress {
	return &AvalancheAddress{chainType: "X"}
}

// NewAvalanchePChainAddress creates a P-Chain address generator
func NewAvalanchePChainAddress() *AvalancheAddress {
	return &AvalancheAddress{chainType: "P"}
}

// NewAvalancheCChainAddress creates a C-Chain address generator (uses Ethereum format)
func NewAvalancheCChainAddress() *EthereumAddress {
	return NewEVMAddress(ChainAvalanche)
}

// ChainID returns the chain identifier
func (a *AvalancheAddress) ChainID() ChainID {
	return ChainAvalanche
}

// Generate creates an Avalanche address from a public key
// For X-Chain and P-Chain: 33 bytes compressed secp256k1
func (a *AvalancheAddress) Generate(publicKey []byte) (string, error) {
	if a.chainType == "C" {
		return "", fmt.Errorf("C-Chain uses Ethereum addresses, use NewAvalancheCChainAddress()")
	}

	if len(publicKey) != 33 {
		return "", fmt.Errorf("Avalanche X/P-Chain requires 33-byte compressed public key")
	}

	// Hash160 of public key
	hash := Hash160(publicKey)

	// Encode with Bech32
	addr, err := Bech32Encode(AvalancheXChainHRP, hash, Bech32Standard)
	if err != nil {
		return "", err
	}

	// Add chain prefix
	return fmt.Sprintf("%s-%s", a.chainType, addr), nil
}

// Validate checks if an Avalanche address is valid
func (a *AvalancheAddress) Validate(address string) bool {
	// Check for chain prefix
	var bech32Part string
	if strings.HasPrefix(address, "X-") || strings.HasPrefix(address, "P-") {
		bech32Part = address[2:]
	} else {
		return false
	}

	_, _, _, err := Bech32Decode(bech32Part)
	return err == nil
}

// DecodeAddress decodes an Avalanche address
func (a *AvalancheAddress) DecodeAddress(address string) (*AddressInfo, error) {
	if !a.Validate(address) {
		return nil, ErrInvalidAddress
	}

	bech32Part := address[2:]
	_, data, _, err := Bech32Decode(bech32Part)
	if err != nil {
		return nil, err
	}

	return &AddressInfo{
		Address:   address,
		PublicKey: data,
		ChainID:   ChainAvalanche,
		Type:      AddressTypeBech32,
	}, nil
}
