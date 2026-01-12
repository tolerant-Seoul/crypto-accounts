package address

import (
	"fmt"
)

// Zcash version bytes
const (
	// Mainnet transparent addresses
	ZcashMainnetP2PKHVersion1 = 0x1C
	ZcashMainnetP2PKHVersion2 = 0xB8
	ZcashMainnetP2SHVersion1  = 0x1C
	ZcashMainnetP2SHVersion2  = 0xBD

	// Testnet transparent addresses
	ZcashTestnetP2PKHVersion1 = 0x1D
	ZcashTestnetP2PKHVersion2 = 0x25
	ZcashTestnetP2SHVersion1  = 0x1C
	ZcashTestnetP2SHVersion2  = 0xBA
)

// ZcashAddress generates Zcash (ZEC) transparent addresses
// Note: Shielded (z-addr) addresses require zk-SNARKs and are not implemented here
type ZcashAddress struct {
	testnet bool
}

// NewZcashAddress creates a new Zcash address generator for mainnet
func NewZcashAddress() *ZcashAddress {
	return &ZcashAddress{testnet: false}
}

// NewZcashTestnetAddress creates a new Zcash address generator for testnet
func NewZcashTestnetAddress() *ZcashAddress {
	return &ZcashAddress{testnet: true}
}

// ChainID returns the chain identifier
func (z *ZcashAddress) ChainID() ChainID {
	return ChainZcash
}

// Generate creates a Zcash transparent P2PKH address from a public key
// Public key should be 33 bytes (compressed) or 65 bytes (uncompressed)
func (z *ZcashAddress) Generate(publicKey []byte) (string, error) {
	if len(publicKey) != 33 && len(publicKey) != 65 {
		return "", fmt.Errorf("invalid public key length: expected 33 or 65, got %d", len(publicKey))
	}

	return z.P2PKH(publicKey)
}

// P2PKH creates a Pay-to-Public-Key-Hash address
// Zcash t1 addresses (mainnet) start with 't1'
func (z *ZcashAddress) P2PKH(publicKey []byte) (string, error) {
	if len(publicKey) != 33 && len(publicKey) != 65 {
		return "", fmt.Errorf("invalid public key length")
	}

	// Hash160 = RIPEMD160(SHA256(publicKey))
	pubKeyHash := Hash160(publicKey)

	// Zcash uses 2-byte version prefix
	var version []byte
	if z.testnet {
		version = []byte{ZcashTestnetP2PKHVersion1, ZcashTestnetP2PKHVersion2}
	} else {
		version = []byte{ZcashMainnetP2PKHVersion1, ZcashMainnetP2PKHVersion2}
	}

	return z.encodeAddress(version, pubKeyHash), nil
}

// P2SH creates a Pay-to-Script-Hash address
// Zcash t3 addresses (mainnet) start with 't3'
func (z *ZcashAddress) P2SH(scriptHash []byte) (string, error) {
	if len(scriptHash) != 20 {
		return "", fmt.Errorf("invalid script hash length: expected 20, got %d", len(scriptHash))
	}

	var version []byte
	if z.testnet {
		version = []byte{ZcashTestnetP2SHVersion1, ZcashTestnetP2SHVersion2}
	} else {
		version = []byte{ZcashMainnetP2SHVersion1, ZcashMainnetP2SHVersion2}
	}

	return z.encodeAddress(version, scriptHash), nil
}

// encodeAddress encodes an address with 2-byte version prefix
func (z *ZcashAddress) encodeAddress(version, hash []byte) string {
	// Combine version and hash
	data := make([]byte, len(version)+len(hash))
	copy(data, version)
	copy(data[len(version):], hash)

	// Calculate checksum
	checksum := DoubleSHA256(data)[:4]

	// Combine all and encode
	result := make([]byte, len(data)+4)
	copy(result, data)
	copy(result[len(data):], checksum)

	return Base58Encode(result)
}

// Validate checks if a Zcash address is valid
func (z *ZcashAddress) Validate(address string) bool {
	// Transparent addresses start with 't'
	if len(address) < 2 {
		return false
	}

	// Check for transparent address prefix
	if address[0] != 't' {
		// Could be shielded address starting with 'z', but we don't support those
		return false
	}

	// Try to decode
	decoded, err := Base58Decode(address)
	if err != nil {
		return false
	}

	// Minimum: 2-byte version + 20-byte hash + 4-byte checksum
	if len(decoded) != 26 {
		return false
	}

	// Verify checksum
	payload := decoded[:22]
	checksum := decoded[22:]
	expectedChecksum := DoubleSHA256(payload)[:4]

	for i := 0; i < 4; i++ {
		if checksum[i] != expectedChecksum[i] {
			return false
		}
	}

	// Verify version bytes
	v1, v2 := decoded[0], decoded[1]

	// Mainnet P2PKH (t1)
	if v1 == ZcashMainnetP2PKHVersion1 && v2 == ZcashMainnetP2PKHVersion2 {
		return true
	}
	// Mainnet P2SH (t3)
	if v1 == ZcashMainnetP2SHVersion1 && v2 == ZcashMainnetP2SHVersion2 {
		return true
	}
	// Testnet P2PKH
	if v1 == ZcashTestnetP2PKHVersion1 && v2 == ZcashTestnetP2PKHVersion2 {
		return true
	}
	// Testnet P2SH
	if v1 == ZcashTestnetP2SHVersion1 && v2 == ZcashTestnetP2SHVersion2 {
		return true
	}

	return false
}

// GetAddressType returns the type of Zcash address
func (z *ZcashAddress) GetAddressType(address string) (string, error) {
	if len(address) < 2 {
		return "", ErrInvalidAddress
	}

	if address[0] == 'z' {
		return "shielded (not supported)", nil
	}

	if address[0] != 't' {
		return "", ErrInvalidAddress
	}

	decoded, err := Base58Decode(address)
	if err != nil {
		return "", err
	}

	if len(decoded) < 2 {
		return "", ErrInvalidAddress
	}

	v1, v2 := decoded[0], decoded[1]

	if v1 == ZcashMainnetP2PKHVersion1 && v2 == ZcashMainnetP2PKHVersion2 {
		return "P2PKH (t1)", nil
	}
	if v1 == ZcashMainnetP2SHVersion1 && v2 == ZcashMainnetP2SHVersion2 {
		return "P2SH (t3)", nil
	}
	if v1 == ZcashTestnetP2PKHVersion1 && v2 == ZcashTestnetP2PKHVersion2 {
		return "P2PKH testnet", nil
	}
	if v1 == ZcashTestnetP2SHVersion1 && v2 == ZcashTestnetP2SHVersion2 {
		return "P2SH testnet", nil
	}

	return "unknown", nil
}

// DecodeAddress decodes a Zcash transparent address
func (z *ZcashAddress) DecodeAddress(address string) (*AddressInfo, error) {
	if !z.Validate(address) {
		return nil, ErrInvalidAddress
	}

	decoded, err := Base58Decode(address)
	if err != nil {
		return nil, err
	}

	return &AddressInfo{
		Address:   address,
		PublicKey: decoded[2:22], // Skip 2-byte version, take 20-byte hash
		ChainID:   ChainZcash,
		Type:      AddressTypeBase58Check,
		Version:   decoded[0],
	}, nil
}
