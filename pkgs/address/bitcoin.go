package address

import (
	"fmt"
)

// Bitcoin address version bytes
const (
	// Mainnet
	BitcoinP2PKHVersion  byte = 0x00 // Prefix: 1
	BitcoinP2SHVersion   byte = 0x05 // Prefix: 3
	BitcoinBech32HRP          = "bc"

	// Testnet
	BitcoinTestnetP2PKHVersion byte = 0x6F // Prefix: m or n
	BitcoinTestnetP2SHVersion  byte = 0xC4 // Prefix: 2
	BitcoinTestnetBech32HRP         = "tb"
)

// BitcoinAddress generates Bitcoin addresses
type BitcoinAddress struct {
	testnet bool
}

// NewBitcoinAddress creates a new Bitcoin address generator
func NewBitcoinAddress(testnet bool) *BitcoinAddress {
	return &BitcoinAddress{testnet: testnet}
}

// ChainID returns the chain identifier
func (b *BitcoinAddress) ChainID() ChainID {
	return ChainBitcoin
}

// P2PKH generates a Pay-to-Public-Key-Hash address (starts with 1 on mainnet)
func (b *BitcoinAddress) P2PKH(publicKey []byte) (string, error) {
	if len(publicKey) != 33 && len(publicKey) != 65 {
		return "", ErrInvalidPublicKey
	}

	// Hash160 = RIPEMD160(SHA256(publicKey))
	pubKeyHash := Hash160(publicKey)

	// Get version byte
	version := BitcoinP2PKHVersion
	if b.testnet {
		version = BitcoinTestnetP2PKHVersion
	}

	return Base58CheckEncode(version, pubKeyHash), nil
}

// P2SH generates a Pay-to-Script-Hash address (starts with 3 on mainnet)
func (b *BitcoinAddress) P2SH(redeemScript []byte) (string, error) {
	if len(redeemScript) == 0 {
		return "", fmt.Errorf("empty redeem script")
	}

	// Hash160 of redeem script
	scriptHash := Hash160(redeemScript)

	// Get version byte
	version := BitcoinP2SHVersion
	if b.testnet {
		version = BitcoinTestnetP2SHVersion
	}

	return Base58CheckEncode(version, scriptHash), nil
}

// P2WPKH generates a native SegWit P2WPKH address (starts with bc1q on mainnet)
func (b *BitcoinAddress) P2WPKH(publicKey []byte) (string, error) {
	// Only compressed public keys are valid for SegWit
	if len(publicKey) != 33 {
		return "", fmt.Errorf("P2WPKH requires compressed public key (33 bytes)")
	}

	// Hash160 = RIPEMD160(SHA256(publicKey))
	pubKeyHash := Hash160(publicKey)

	// Get HRP
	hrp := BitcoinBech32HRP
	if b.testnet {
		hrp = BitcoinTestnetBech32HRP
	}

	// Witness version 0 uses Bech32 (not Bech32m)
	return SegWitEncode(hrp, 0, pubKeyHash)
}

// P2WSH generates a native SegWit P2WSH address (starts with bc1q on mainnet)
func (b *BitcoinAddress) P2WSH(witnessScript []byte) (string, error) {
	if len(witnessScript) == 0 {
		return "", fmt.Errorf("empty witness script")
	}

	// SHA256 of witness script (not Hash160!)
	scriptHash := SHA256Hash(witnessScript)

	// Get HRP
	hrp := BitcoinBech32HRP
	if b.testnet {
		hrp = BitcoinTestnetBech32HRP
	}

	// Witness version 0 uses Bech32 (not Bech32m)
	return SegWitEncode(hrp, 0, scriptHash)
}

// P2TR generates a Taproot address (starts with bc1p on mainnet)
func (b *BitcoinAddress) P2TR(taprootKey []byte) (string, error) {
	if len(taprootKey) != 32 {
		return "", fmt.Errorf("P2TR requires 32-byte x-only public key")
	}

	// Get HRP
	hrp := BitcoinBech32HRP
	if b.testnet {
		hrp = BitcoinTestnetBech32HRP
	}

	// Witness version 1 uses Bech32m
	return SegWitEncode(hrp, 1, taprootKey)
}

// Generate creates a P2PKH address by default
func (b *BitcoinAddress) Generate(publicKey []byte) (string, error) {
	return b.P2PKH(publicKey)
}

// Validate checks if an address is valid
func (b *BitcoinAddress) Validate(address string) bool {
	// Check for Bech32 addresses
	if len(address) > 4 {
		prefix := address[:3]
		if prefix == "bc1" || prefix == "tb1" {
			_, _, _, err := SegWitDecode(address)
			return err == nil
		}
	}

	// Check for Base58Check addresses
	version, _, err := Base58CheckDecode(address)
	if err != nil {
		return false
	}

	// Validate version byte
	switch version {
	case BitcoinP2PKHVersion, BitcoinP2SHVersion:
		return !b.testnet
	case BitcoinTestnetP2PKHVersion, BitcoinTestnetP2SHVersion:
		return b.testnet
	}

	return false
}

// DecodeAddress decodes a Bitcoin address and returns address info
func (b *BitcoinAddress) DecodeAddress(address string) (*AddressInfo, error) {
	info := &AddressInfo{
		Address: address,
		ChainID: ChainBitcoin,
	}

	// Check for Bech32 addresses
	if len(address) > 4 {
		prefix := address[:3]
		if prefix == "bc1" || prefix == "tb1" {
			hrp, witnessVersion, program, err := SegWitDecode(address)
			if err != nil {
				return nil, err
			}

			info.Type = AddressTypeBitcoinBech32
			info.PublicKey = program

			// Determine version based on witness program length and version
			if witnessVersion == 0 {
				if len(program) == 20 {
					// P2WPKH
				} else if len(program) == 32 {
					// P2WSH
				}
			}

			// Check HRP
			if (hrp == "bc" && b.testnet) || (hrp == "tb" && !b.testnet) {
				return nil, fmt.Errorf("network mismatch")
			}

			return info, nil
		}
	}

	// Decode Base58Check
	version, payload, err := Base58CheckDecode(address)
	if err != nil {
		return nil, err
	}

	info.Version = version
	info.PublicKey = payload

	switch version {
	case BitcoinP2PKHVersion, BitcoinTestnetP2PKHVersion:
		info.Type = AddressTypeBitcoinP2PKH
	case BitcoinP2SHVersion, BitcoinTestnetP2SHVersion:
		info.Type = AddressTypeBitcoinP2SH
	default:
		return nil, ErrInvalidVersion
	}

	return info, nil
}
