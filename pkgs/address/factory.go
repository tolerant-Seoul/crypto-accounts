package address

import (
	"fmt"
)

// Factory provides a unified interface to create address generators for different chains
type Factory struct {
	generators map[ChainID]AddressGenerator
}

// NewFactory creates a new address generator factory
func NewFactory() *Factory {
	f := &Factory{
		generators: make(map[ChainID]AddressGenerator),
	}
	f.registerDefaults()
	return f
}

// registerDefaults registers all default address generators
func (f *Factory) registerDefaults() {
	// Bitcoin-family
	f.Register(ChainBitcoin, NewBitcoinAddress(false))
	f.Register(ChainLitecoin, NewLitecoinAddress(false))
	f.Register(ChainDogecoin, NewDogecoinAddress(false))
	f.Register(ChainBitcoinCash, NewBitcoinCashAddress(false))

	// Ethereum-family (EVM)
	f.Register(ChainEthereum, NewEthereumAddress())
	f.Register(ChainBSC, NewEVMAddress(ChainBSC))
	f.Register(ChainPolygon, NewEVMAddress(ChainPolygon))
	f.Register(ChainFantom, NewEVMAddress(ChainFantom))
	f.Register(ChainOptimism, NewEVMAddress(ChainOptimism))
	f.Register(ChainArbitrum, NewEVMAddress(ChainArbitrum))
	f.Register(ChainVeChain, NewEVMAddress(ChainVeChain))
	f.Register(ChainTheta, NewEVMAddress(ChainTheta))
	f.Register(ChainEthereumClassic, NewEVMAddress(ChainEthereumClassic))
	f.Register(ChainAvalanche, NewAvalancheCChainAddress()) // C-Chain is EVM

	// Cosmos-family (Bech32)
	f.Register(ChainCosmos, NewCosmosAddress())
	f.Register(ChainBinanceBEP2, NewBinanceBEP2Address())
	f.Register(ChainSei, NewSeiAddress())

	// TRON
	f.Register(ChainTron, NewTronAddress(false))

	// Ripple
	f.Register(ChainRipple, NewRippleAddress())

	// Ed25519-based
	f.Register(ChainSolana, NewSolanaAddress())
	f.Register(ChainStellar, NewStellarAddress())
	f.Register(ChainAlgorand, NewAlgorandAddress())
	f.Register(ChainNEAR, NewNEARAddress())
	f.Register(ChainCardano, NewCardanoAddress())

	// Polkadot-family (SS58)
	f.Register(ChainPolkadot, NewPolkadotAddress())

	// New generation chains
	f.Register(ChainAptos, NewAptosAddress())
	f.Register(ChainSui, NewSuiAddress())
}

// Register adds a new address generator to the factory
func (f *Factory) Register(chainID ChainID, generator AddressGenerator) {
	f.generators[chainID] = generator
}

// Get returns an address generator for the specified chain
func (f *Factory) Get(chainID ChainID) (AddressGenerator, error) {
	gen, ok := f.generators[chainID]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedChain, chainID)
	}
	return gen, nil
}

// Generate creates an address for the specified chain from a public key
func (f *Factory) Generate(chainID ChainID, publicKey []byte) (string, error) {
	gen, err := f.Get(chainID)
	if err != nil {
		return "", err
	}
	return gen.Generate(publicKey)
}

// Validate checks if an address is valid for the specified chain
func (f *Factory) Validate(chainID ChainID, address string) bool {
	gen, err := f.Get(chainID)
	if err != nil {
		return false
	}
	return gen.Validate(address)
}

// ListSupportedChains returns all supported chain IDs
func (f *Factory) ListSupportedChains() []ChainID {
	chains := make([]ChainID, 0, len(f.generators))
	for chainID := range f.generators {
		chains = append(chains, chainID)
	}
	return chains
}

// ChainInfo contains information about a supported chain
type ChainInfo struct {
	ID          ChainID
	Name        string
	Symbol      string
	AddressType string
	Description string
}

// GetChainInfo returns information about a chain
func GetChainInfo(chainID ChainID) *ChainInfo {
	chainInfoMap := map[ChainID]*ChainInfo{
		ChainBitcoin:         {ChainBitcoin, "Bitcoin", "BTC", "Base58Check/Bech32", "P2PKH, P2SH, SegWit addresses"},
		ChainEthereum:        {ChainEthereum, "Ethereum", "ETH", "Keccak256", "EIP-55 checksummed addresses"},
		ChainLitecoin:        {ChainLitecoin, "Litecoin", "LTC", "Base58Check/Bech32", "Similar to Bitcoin with different prefixes"},
		ChainDogecoin:        {ChainDogecoin, "Dogecoin", "DOGE", "Base58Check", "Starts with 'D'"},
		ChainRipple:          {ChainRipple, "Ripple", "XRP", "Base58 (Ripple)", "Starts with 'r'"},
		ChainStellar:         {ChainStellar, "Stellar", "XLM", "Base32", "Starts with 'G'"},
		ChainCardano:         {ChainCardano, "Cardano", "ADA", "Bech32", "Starts with 'addr1'"},
		ChainPolkadot:        {ChainPolkadot, "Polkadot", "DOT", "SS58", "Network-specific prefixes"},
		ChainSolana:          {ChainSolana, "Solana", "SOL", "Base58", "32-byte public key"},
		ChainAvalanche:       {ChainAvalanche, "Avalanche", "AVAX", "Bech32/Ethereum", "X/P-Chain: Bech32, C-Chain: Ethereum"},
		ChainCosmos:          {ChainCosmos, "Cosmos", "ATOM", "Bech32", "Starts with 'cosmos'"},
		ChainTron:            {ChainTron, "TRON", "TRX", "Base58Check", "Starts with 'T'"},
		ChainTezos:           {ChainTezos, "Tezos", "XTZ", "Base58Check", "Starts with 'tz'"},
		ChainMonero:          {ChainMonero, "Monero", "XMR", "Base58", "95 characters, starts with '4'"},
		ChainBitcoinCash:     {ChainBitcoinCash, "Bitcoin Cash", "BCH", "CashAddr", "Starts with 'bitcoincash:'"},
		ChainZcash:           {ChainZcash, "Zcash", "ZEC", "Base58Check", "Transparent: 't', Shielded: 'z'"},
		ChainBSC:             {ChainBSC, "BNB Smart Chain", "BNB", "Keccak256", "Same as Ethereum"},
		ChainPolygon:         {ChainPolygon, "Polygon", "MATIC", "Keccak256", "Same as Ethereum"},
		ChainFantom:          {ChainFantom, "Fantom", "FTM", "Keccak256", "Same as Ethereum"},
		ChainOptimism:        {ChainOptimism, "Optimism", "OP", "Keccak256", "Same as Ethereum"},
		ChainArbitrum:        {ChainArbitrum, "Arbitrum", "ARB", "Keccak256", "Same as Ethereum"},
		ChainVeChain:         {ChainVeChain, "VeChain", "VET", "Keccak256", "Same as Ethereum"},
		ChainTheta:           {ChainTheta, "Theta", "THETA", "Keccak256", "Same as Ethereum"},
		ChainBinanceBEP2:     {ChainBinanceBEP2, "Binance Chain", "BNB", "Bech32", "Starts with 'bnb'"},
		ChainNEAR:            {ChainNEAR, "NEAR Protocol", "NEAR", "Hex/Named", "64 hex chars or named accounts"},
		ChainAlgorand:        {ChainAlgorand, "Algorand", "ALGO", "Base32", "58 characters"},
		ChainAptos:           {ChainAptos, "Aptos", "APT", "Hex", "0x-prefixed, 64 hex chars"},
		ChainSui:             {ChainSui, "Sui", "SUI", "Hex", "0x-prefixed, 64 hex chars"},
		ChainSei:             {ChainSei, "Sei", "SEI", "Bech32/Ethereum", "Dual address system"},
		ChainEthereumClassic: {ChainEthereumClassic, "Ethereum Classic", "ETC", "Keccak256", "Same as Ethereum"},
	}

	info, ok := chainInfoMap[chainID]
	if !ok {
		return nil
	}
	return info
}

// ListAllChainInfo returns information about all supported chains
func ListAllChainInfo() []*ChainInfo {
	chains := []ChainID{
		ChainBitcoin, ChainEthereum, ChainLitecoin, ChainDogecoin, ChainRipple,
		ChainStellar, ChainCardano, ChainPolkadot, ChainSolana, ChainAvalanche, ChainCosmos,
		ChainTron, ChainBitcoinCash, ChainBSC, ChainPolygon, ChainFantom,
		ChainOptimism, ChainArbitrum, ChainVeChain, ChainTheta, ChainBinanceBEP2,
		ChainNEAR, ChainAlgorand, ChainAptos, ChainSui, ChainSei, ChainEthereumClassic,
	}

	infos := make([]*ChainInfo, 0, len(chains))
	for _, chainID := range chains {
		if info := GetChainInfo(chainID); info != nil {
			infos = append(infos, info)
		}
	}
	return infos
}

// DefaultFactory is the default global factory instance
var DefaultFactory = NewFactory()

// Generate creates an address using the default factory
func Generate(chainID ChainID, publicKey []byte) (string, error) {
	return DefaultFactory.Generate(chainID, publicKey)
}

// Validate checks an address using the default factory
func Validate(chainID ChainID, address string) bool {
	return DefaultFactory.Validate(chainID, address)
}
