package address

// Litecoin address version bytes
const (
	// Mainnet
	LitecoinP2PKHVersion byte = 0x30 // Prefix: L
	LitecoinP2SHVersion  byte = 0x32 // Prefix: M
	LitecoinBech32HRP         = "ltc"

	// Testnet
	LitecoinTestnetP2PKHVersion byte = 0x6F // Prefix: m or n
	LitecoinTestnetP2SHVersion  byte = 0x3A // Prefix: Q
	LitecoinTestnetBech32HRP         = "tltc"
)

// LitecoinAddress generates Litecoin addresses
type LitecoinAddress struct {
	testnet bool
}

// NewLitecoinAddress creates a new Litecoin address generator
func NewLitecoinAddress(testnet bool) *LitecoinAddress {
	return &LitecoinAddress{testnet: testnet}
}

// ChainID returns the chain identifier
func (l *LitecoinAddress) ChainID() ChainID {
	return ChainLitecoin
}

// P2PKH generates a Pay-to-Public-Key-Hash address (starts with L on mainnet)
func (l *LitecoinAddress) P2PKH(publicKey []byte) (string, error) {
	if len(publicKey) != 33 && len(publicKey) != 65 {
		return "", ErrInvalidPublicKey
	}

	pubKeyHash := Hash160(publicKey)

	version := LitecoinP2PKHVersion
	if l.testnet {
		version = LitecoinTestnetP2PKHVersion
	}

	return Base58CheckEncode(version, pubKeyHash), nil
}

// P2SH generates a Pay-to-Script-Hash address (starts with M on mainnet)
func (l *LitecoinAddress) P2SH(redeemScript []byte) (string, error) {
	if len(redeemScript) == 0 {
		return "", ErrInvalidPublicKey
	}

	scriptHash := Hash160(redeemScript)

	version := LitecoinP2SHVersion
	if l.testnet {
		version = LitecoinTestnetP2SHVersion
	}

	return Base58CheckEncode(version, scriptHash), nil
}

// Bech32 generates a native SegWit address (starts with ltc1 on mainnet)
func (l *LitecoinAddress) Bech32(publicKey []byte) (string, error) {
	if len(publicKey) != 33 {
		return "", ErrInvalidPublicKey
	}

	pubKeyHash := Hash160(publicKey)

	hrp := LitecoinBech32HRP
	if l.testnet {
		hrp = LitecoinTestnetBech32HRP
	}

	return SegWitEncode(hrp, 0, pubKeyHash)
}

// Generate creates a P2PKH address by default
func (l *LitecoinAddress) Generate(publicKey []byte) (string, error) {
	return l.P2PKH(publicKey)
}

// Validate checks if an address is valid
func (l *LitecoinAddress) Validate(address string) bool {
	// Check for Bech32 addresses
	if len(address) > 4 {
		prefix := address[:4]
		if prefix == "ltc1" || prefix == "tltc" {
			_, _, _, err := SegWitDecode(address)
			return err == nil
		}
	}

	// Check for Base58Check addresses
	version, _, err := Base58CheckDecode(address)
	if err != nil {
		return false
	}

	switch version {
	case LitecoinP2PKHVersion, LitecoinP2SHVersion:
		return !l.testnet
	case LitecoinTestnetP2PKHVersion, LitecoinTestnetP2SHVersion:
		return l.testnet
	}

	return false
}
