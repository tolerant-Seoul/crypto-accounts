// Package address provides chain-specific address generation from public keys.
package address

import (
	"errors"
)

// Common errors
var (
	ErrInvalidPublicKey   = errors.New("invalid public key")
	ErrInvalidPrivateKey  = errors.New("invalid private key")
	ErrUnsupportedChain   = errors.New("unsupported chain")
	ErrInvalidAddress     = errors.New("invalid address")
	ErrInvalidChecksum    = errors.New("invalid checksum")
	ErrInvalidVersion     = errors.New("invalid version byte")
	ErrInvalidKeyLength   = errors.New("invalid key length")
)

// AddressType represents the type of address format
type AddressType int

const (
	// Bitcoin address types
	AddressTypeBitcoinP2PKH AddressType = iota
	AddressTypeBitcoinP2SH
	AddressTypeBitcoinBech32

	// Ethereum-style
	AddressTypeEthereum

	// Other formats
	AddressTypeBech32
	AddressTypeBase58Check
	AddressTypeBase58
	AddressTypeBase32
	AddressTypeSS58
	AddressTypeCashAddr
)

// ChainID represents different blockchain networks
type ChainID string

const (
	// Major chains
	ChainBitcoin      ChainID = "btc"
	ChainEthereum     ChainID = "eth"
	ChainLitecoin     ChainID = "ltc"
	ChainDogecoin     ChainID = "doge"
	ChainRipple       ChainID = "xrp"
	ChainStellar      ChainID = "xlm"
	ChainCardano      ChainID = "ada"
	ChainPolkadot     ChainID = "dot"
	ChainSolana       ChainID = "sol"
	ChainAvalanche    ChainID = "avax"
	ChainCosmos       ChainID = "atom"
	ChainTron         ChainID = "trx"
	ChainTezos        ChainID = "xtz"
	ChainMonero       ChainID = "xmr"
	ChainBitcoinCash  ChainID = "bch"
	ChainZcash        ChainID = "zec"

	// EVM-compatible chains
	ChainBSC          ChainID = "bsc"
	ChainPolygon      ChainID = "matic"
	ChainFantom       ChainID = "ftm"
	ChainOptimism     ChainID = "op"
	ChainArbitrum     ChainID = "arb"
	ChainVeChain      ChainID = "vet"
	ChainTheta        ChainID = "theta"

	// Other chains
	ChainBinanceBEP2  ChainID = "bnb"
	ChainNEAR         ChainID = "near"
	ChainAlgorand     ChainID = "algo"
	ChainEOS          ChainID = "eos"
	ChainFlow         ChainID = "flow"
	ChainAptos        ChainID = "apt"
	ChainSui          ChainID = "sui"
	ChainSei          ChainID = "sei"
	ChainStacks       ChainID = "stx"
	ChainFilecoin     ChainID = "fil"
	ChainArweave      ChainID = "ar"
	ChainKaspa        ChainID = "kas"
	ChainHedera       ChainID = "hbar"
	ChainICP          ChainID = "icp"
	ChainDash         ChainID = "dash"
	ChainEthereumClassic ChainID = "etc"
)

// AddressGenerator is the interface for generating addresses
type AddressGenerator interface {
	// Generate creates an address from a public key
	Generate(publicKey []byte) (string, error)

	// Validate checks if an address is valid
	Validate(address string) bool

	// ChainID returns the chain identifier
	ChainID() ChainID
}

// AddressInfo contains information about a generated address
type AddressInfo struct {
	Address    string
	PublicKey  []byte
	ChainID    ChainID
	Type       AddressType
	Version    byte
}
