// Package bip44 implements BIP-44 multi-account hierarchy for deterministic wallets.
package bip44

// CoinType represents a cryptocurrency coin type as defined in SLIP-44.
// https://github.com/satoshilabs/slips/blob/master/slip-0044.md
type CoinType uint32

// Common coin types from SLIP-44 registry.
const (
	CoinTypeBitcoin         CoinType = 0
	CoinTypeTestnet         CoinType = 1
	CoinTypeLitecoin        CoinType = 2
	CoinTypeDogecoin        CoinType = 3
	CoinTypeDash            CoinType = 5
	CoinTypeEthereum        CoinType = 60
	CoinTypeEthereumClassic CoinType = 61
	CoinTypeRipple          CoinType = 144
	CoinTypeBitcoinCash     CoinType = 145
	CoinTypeStellar         CoinType = 148
	CoinTypeTron            CoinType = 195
	CoinTypeBinance         CoinType = 714
	CoinTypeSolana          CoinType = 501
	CoinTypePolygon         CoinType = 966
	CoinTypeAvalanche       CoinType = 9000
)

// CoinInfo contains metadata about a cryptocurrency.
type CoinInfo struct {
	Type     CoinType
	Symbol   string
	Name     string
	Decimals int
}

// coinRegistry maps coin types to their metadata.
var coinRegistry = map[CoinType]CoinInfo{
	CoinTypeBitcoin: {
		Type:     CoinTypeBitcoin,
		Symbol:   "BTC",
		Name:     "Bitcoin",
		Decimals: 8,
	},
	CoinTypeTestnet: {
		Type:     CoinTypeTestnet,
		Symbol:   "TEST",
		Name:     "Testnet (all coins)",
		Decimals: 8,
	},
	CoinTypeLitecoin: {
		Type:     CoinTypeLitecoin,
		Symbol:   "LTC",
		Name:     "Litecoin",
		Decimals: 8,
	},
	CoinTypeDogecoin: {
		Type:     CoinTypeDogecoin,
		Symbol:   "DOGE",
		Name:     "Dogecoin",
		Decimals: 8,
	},
	CoinTypeDash: {
		Type:     CoinTypeDash,
		Symbol:   "DASH",
		Name:     "Dash",
		Decimals: 8,
	},
	CoinTypeEthereum: {
		Type:     CoinTypeEthereum,
		Symbol:   "ETH",
		Name:     "Ethereum",
		Decimals: 18,
	},
	CoinTypeEthereumClassic: {
		Type:     CoinTypeEthereumClassic,
		Symbol:   "ETC",
		Name:     "Ethereum Classic",
		Decimals: 18,
	},
	CoinTypeRipple: {
		Type:     CoinTypeRipple,
		Symbol:   "XRP",
		Name:     "Ripple",
		Decimals: 6,
	},
	CoinTypeBitcoinCash: {
		Type:     CoinTypeBitcoinCash,
		Symbol:   "BCH",
		Name:     "Bitcoin Cash",
		Decimals: 8,
	},
	CoinTypeStellar: {
		Type:     CoinTypeStellar,
		Symbol:   "XLM",
		Name:     "Stellar",
		Decimals: 7,
	},
	CoinTypeTron: {
		Type:     CoinTypeTron,
		Symbol:   "TRX",
		Name:     "Tron",
		Decimals: 6,
	},
	CoinTypeBinance: {
		Type:     CoinTypeBinance,
		Symbol:   "BNB",
		Name:     "Binance",
		Decimals: 8,
	},
	CoinTypeSolana: {
		Type:     CoinTypeSolana,
		Symbol:   "SOL",
		Name:     "Solana",
		Decimals: 9,
	},
	CoinTypePolygon: {
		Type:     CoinTypePolygon,
		Symbol:   "MATIC",
		Name:     "Polygon",
		Decimals: 18,
	},
	CoinTypeAvalanche: {
		Type:     CoinTypeAvalanche,
		Symbol:   "AVAX",
		Name:     "Avalanche",
		Decimals: 18,
	},
}

// GetCoinInfo returns the coin information for a given coin type.
// Returns nil if the coin type is not registered.
func GetCoinInfo(coinType CoinType) *CoinInfo {
	if info, ok := coinRegistry[coinType]; ok {
		return &info
	}
	return nil
}

// RegisterCoin registers a custom coin type.
func RegisterCoin(info CoinInfo) {
	coinRegistry[info.Type] = info
}

// ListCoins returns all registered coin types.
func ListCoins() []CoinInfo {
	coins := make([]CoinInfo, 0, len(coinRegistry))
	for _, info := range coinRegistry {
		coins = append(coins, info)
	}
	return coins
}
