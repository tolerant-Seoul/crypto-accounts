package address

import (
	"fmt"
)

// Cosmos HRPs for different chains
const (
	CosmosHRP        = "cosmos"
	OsmosisHRP       = "osmo"
	TerraHRP         = "terra"
	JunoHRP          = "juno"
	SecretHRP        = "secret"
	AkashHRP         = "akash"
	KavaHRP          = "kava"
	EvmosHRP         = "evmos"
	InjectiveHRP     = "inj"
	SeiHRP           = "sei"
	CelestiaHRP      = "celestia"
	BinanceBEP2HRP   = "bnb"
)

// CosmosAddress generates Cosmos SDK-based addresses
// Used by: Cosmos Hub, Osmosis, Terra, Juno, Secret Network, etc.
type CosmosAddress struct {
	hrp     string
	chainID ChainID
}

// NewCosmosAddress creates a new Cosmos Hub address generator
func NewCosmosAddress() *CosmosAddress {
	return &CosmosAddress{hrp: CosmosHRP, chainID: ChainCosmos}
}

// NewCosmosAddressWithHRP creates a Cosmos-based address generator with custom HRP
func NewCosmosAddressWithHRP(hrp string, chainID ChainID) *CosmosAddress {
	return &CosmosAddress{hrp: hrp, chainID: chainID}
}

// NewBinanceBEP2Address creates a Binance Chain (BEP2) address generator
func NewBinanceBEP2Address() *CosmosAddress {
	return &CosmosAddress{hrp: BinanceBEP2HRP, chainID: ChainBinanceBEP2}
}

// NewSeiAddress creates a Sei address generator
func NewSeiAddress() *CosmosAddress {
	return &CosmosAddress{hrp: SeiHRP, chainID: ChainSei}
}

// ChainID returns the chain identifier
func (c *CosmosAddress) ChainID() ChainID {
	return c.chainID
}

// HRP returns the human-readable prefix
func (c *CosmosAddress) HRP() string {
	return c.hrp
}

// Generate creates a Cosmos address from a public key
// Public key should be 33 bytes (compressed secp256k1)
func (c *CosmosAddress) Generate(publicKey []byte) (string, error) {
	if len(publicKey) != 33 {
		return "", fmt.Errorf("Cosmos requires 33-byte compressed public key")
	}

	// Hash160 = RIPEMD160(SHA256(publicKey))
	pubKeyHash := Hash160(publicKey)

	// Encode with Bech32
	return Bech32Encode(c.hrp, pubKeyHash, Bech32Standard)
}

// GenerateValidator creates a validator operator address (valoper)
func (c *CosmosAddress) GenerateValidator(publicKey []byte) (string, error) {
	if len(publicKey) != 33 {
		return "", fmt.Errorf("Cosmos requires 33-byte compressed public key")
	}

	pubKeyHash := Hash160(publicKey)

	// Use valoper prefix
	hrp := c.hrp + "valoper"

	return Bech32Encode(hrp, pubKeyHash, Bech32Standard)
}

// GenerateConsensus creates a consensus node address (valcons)
func (c *CosmosAddress) GenerateConsensus(publicKey []byte) (string, error) {
	if len(publicKey) != 33 {
		return "", fmt.Errorf("Cosmos requires 33-byte compressed public key")
	}

	pubKeyHash := Hash160(publicKey)

	// Use valcons prefix
	hrp := c.hrp + "valcons"

	return Bech32Encode(hrp, pubKeyHash, Bech32Standard)
}

// Validate checks if an address is valid
func (c *CosmosAddress) Validate(address string) bool {
	hrp, _, _, err := Bech32Decode(address)
	if err != nil {
		return false
	}

	// Check if HRP matches or is a derivative (valoper, valcons)
	if hrp != c.hrp && hrp != c.hrp+"valoper" && hrp != c.hrp+"valcons" {
		return false
	}

	return true
}

// DecodeAddress decodes a Cosmos address
func (c *CosmosAddress) DecodeAddress(address string) (*AddressInfo, error) {
	hrp, data, _, err := Bech32Decode(address)
	if err != nil {
		return nil, err
	}

	if hrp != c.hrp && hrp != c.hrp+"valoper" && hrp != c.hrp+"valcons" {
		return nil, fmt.Errorf("invalid HRP: expected %s, got %s", c.hrp, hrp)
	}

	return &AddressInfo{
		Address:   address,
		PublicKey: data,
		ChainID:   c.chainID,
		Type:      AddressTypeBech32,
	}, nil
}

// CosmosBasedChains returns a map of Cosmos-based chain generators
func CosmosBasedChains() map[ChainID]*CosmosAddress {
	return map[ChainID]*CosmosAddress{
		ChainCosmos:      NewCosmosAddress(),
		ChainBinanceBEP2: NewBinanceBEP2Address(),
		ChainSei:         NewSeiAddress(),
	}
}
