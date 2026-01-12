package address

// Dogecoin address version bytes
const (
	// Mainnet
	DogecoinP2PKHVersion byte = 0x1E // Prefix: D
	DogecoinP2SHVersion  byte = 0x16 // Prefix: 9 or A

	// Testnet
	DogecoinTestnetP2PKHVersion byte = 0x71 // Prefix: n
	DogecoinTestnetP2SHVersion  byte = 0xC4 // Prefix: 2
)

// DogecoinAddress generates Dogecoin addresses
type DogecoinAddress struct {
	testnet bool
}

// NewDogecoinAddress creates a new Dogecoin address generator
func NewDogecoinAddress(testnet bool) *DogecoinAddress {
	return &DogecoinAddress{testnet: testnet}
}

// ChainID returns the chain identifier
func (d *DogecoinAddress) ChainID() ChainID {
	return ChainDogecoin
}

// P2PKH generates a Pay-to-Public-Key-Hash address (starts with D on mainnet)
func (d *DogecoinAddress) P2PKH(publicKey []byte) (string, error) {
	if len(publicKey) != 33 && len(publicKey) != 65 {
		return "", ErrInvalidPublicKey
	}

	pubKeyHash := Hash160(publicKey)

	version := DogecoinP2PKHVersion
	if d.testnet {
		version = DogecoinTestnetP2PKHVersion
	}

	return Base58CheckEncode(version, pubKeyHash), nil
}

// P2SH generates a Pay-to-Script-Hash address
func (d *DogecoinAddress) P2SH(redeemScript []byte) (string, error) {
	if len(redeemScript) == 0 {
		return "", ErrInvalidPublicKey
	}

	scriptHash := Hash160(redeemScript)

	version := DogecoinP2SHVersion
	if d.testnet {
		version = DogecoinTestnetP2SHVersion
	}

	return Base58CheckEncode(version, scriptHash), nil
}

// Generate creates a P2PKH address by default
func (d *DogecoinAddress) Generate(publicKey []byte) (string, error) {
	return d.P2PKH(publicKey)
}

// Validate checks if an address is valid
func (d *DogecoinAddress) Validate(address string) bool {
	version, _, err := Base58CheckDecode(address)
	if err != nil {
		return false
	}

	switch version {
	case DogecoinP2PKHVersion, DogecoinP2SHVersion:
		return !d.testnet
	case DogecoinTestnetP2PKHVersion, DogecoinTestnetP2SHVersion:
		return d.testnet
	}

	return false
}
