package address

import (
	"fmt"

	"golang.org/x/crypto/sha3"
)

// Monero network bytes
const (
	MoneroMainnetStandard    = 0x12 // Standard address (4...)
	MoneroMainnetIntegrated  = 0x13 // Integrated address (4...)
	MoneroMainnetSubaddress  = 0x2A // Subaddress (8...)
	MoneroTestnetStandard    = 0x35 // Testnet standard
	MoneroTestnetIntegrated  = 0x36 // Testnet integrated
	MoneroTestnetSubaddress  = 0x3F // Testnet subaddress
	MoneroStagenetStandard   = 0x18 // Stagenet standard
	MoneroStagenetIntegrated = 0x19 // Stagenet integrated
	MoneroStagenetSubaddress = 0x24 // Stagenet subaddress
)

// MoneroAddress generates Monero (XMR) addresses
// Monero uses dual-key cryptography with spend key and view key
type MoneroAddress struct {
	testnet bool
}

// NewMoneroAddress creates a new Monero address generator for mainnet
func NewMoneroAddress() *MoneroAddress {
	return &MoneroAddress{testnet: false}
}

// NewMoneroTestnetAddress creates a new Monero address generator for testnet
func NewMoneroTestnetAddress() *MoneroAddress {
	return &MoneroAddress{testnet: true}
}

// ChainID returns the chain identifier
func (m *MoneroAddress) ChainID() ChainID {
	return ChainMonero
}

// Generate creates a Monero address from spend and view public keys
// publicKey should be 64 bytes: 32-byte spend key + 32-byte view key
func (m *MoneroAddress) Generate(publicKey []byte) (string, error) {
	if len(publicKey) != 64 {
		return "", fmt.Errorf("invalid public key length: expected 64 (32+32), got %d", len(publicKey))
	}

	spendKey := publicKey[:32]
	viewKey := publicKey[32:]

	return m.GenerateStandard(spendKey, viewKey)
}

// GenerateStandard creates a standard Monero address
func (m *MoneroAddress) GenerateStandard(spendPubKey, viewPubKey []byte) (string, error) {
	if len(spendPubKey) != 32 || len(viewPubKey) != 32 {
		return "", fmt.Errorf("both keys must be 32 bytes")
	}

	// Get network byte
	var netByte byte
	if m.testnet {
		netByte = MoneroTestnetStandard
	} else {
		netByte = MoneroMainnetStandard
	}

	// Build payload: network_byte + spend_key + view_key
	payload := make([]byte, 1+32+32)
	payload[0] = netByte
	copy(payload[1:33], spendPubKey)
	copy(payload[33:65], viewPubKey)

	// Calculate Keccak-256 checksum (first 4 bytes)
	checksum := keccak256(payload)[:4]

	// Combine payload and checksum
	full := append(payload, checksum...)

	// Encode with Monero Base58
	return moneroBase58Encode(full), nil
}

// GenerateSubaddress creates a Monero subaddress
func (m *MoneroAddress) GenerateSubaddress(spendPubKey, viewPubKey []byte) (string, error) {
	if len(spendPubKey) != 32 || len(viewPubKey) != 32 {
		return "", fmt.Errorf("both keys must be 32 bytes")
	}

	var netByte byte
	if m.testnet {
		netByte = MoneroTestnetSubaddress
	} else {
		netByte = MoneroMainnetSubaddress
	}

	payload := make([]byte, 1+32+32)
	payload[0] = netByte
	copy(payload[1:33], spendPubKey)
	copy(payload[33:65], viewPubKey)

	checksum := keccak256(payload)[:4]
	full := append(payload, checksum...)

	return moneroBase58Encode(full), nil
}

// Validate checks if a Monero address is valid
func (m *MoneroAddress) Validate(address string) bool {
	// Monero addresses are 95 characters (standard/subaddress) or 106 characters (integrated)
	if len(address) != 95 && len(address) != 106 {
		return false
	}

	// Decode from Monero Base58
	decoded, err := moneroBase58Decode(address)
	if err != nil {
		return false
	}

	// Standard/Subaddress: 1 + 32 + 32 + 4 = 69 bytes
	// Integrated: 1 + 32 + 32 + 8 + 4 = 77 bytes
	if len(decoded) != 69 && len(decoded) != 77 {
		return false
	}

	// Verify network byte
	netByte := decoded[0]
	validMainnet := netByte == MoneroMainnetStandard || netByte == MoneroMainnetIntegrated || netByte == MoneroMainnetSubaddress
	validTestnet := netByte == MoneroTestnetStandard || netByte == MoneroTestnetIntegrated || netByte == MoneroTestnetSubaddress
	validStagenet := netByte == MoneroStagenetStandard || netByte == MoneroStagenetIntegrated || netByte == MoneroStagenetSubaddress

	if m.testnet {
		if !validTestnet {
			return false
		}
	} else {
		if !validMainnet && !validStagenet {
			return false
		}
	}

	// Verify checksum
	payloadLen := len(decoded) - 4
	payload := decoded[:payloadLen]
	checksum := decoded[payloadLen:]
	expectedChecksum := keccak256(payload)[:4]

	for i := 0; i < 4; i++ {
		if checksum[i] != expectedChecksum[i] {
			return false
		}
	}

	return true
}

// GetAddressType returns the type of Monero address
func (m *MoneroAddress) GetAddressType(address string) (string, error) {
	decoded, err := moneroBase58Decode(address)
	if err != nil {
		return "", ErrInvalidAddress
	}

	netByte := decoded[0]
	switch netByte {
	case MoneroMainnetStandard:
		return "Mainnet Standard", nil
	case MoneroMainnetIntegrated:
		return "Mainnet Integrated", nil
	case MoneroMainnetSubaddress:
		return "Mainnet Subaddress", nil
	case MoneroTestnetStandard:
		return "Testnet Standard", nil
	case MoneroTestnetIntegrated:
		return "Testnet Integrated", nil
	case MoneroTestnetSubaddress:
		return "Testnet Subaddress", nil
	case MoneroStagenetStandard:
		return "Stagenet Standard", nil
	case MoneroStagenetIntegrated:
		return "Stagenet Integrated", nil
	case MoneroStagenetSubaddress:
		return "Stagenet Subaddress", nil
	default:
		return "Unknown", nil
	}
}

// DecodeAddress decodes a Monero address
func (m *MoneroAddress) DecodeAddress(address string) (*AddressInfo, error) {
	if !m.Validate(address) {
		return nil, ErrInvalidAddress
	}

	decoded, err := moneroBase58Decode(address)
	if err != nil {
		return nil, err
	}

	// Extract keys (skip network byte, exclude checksum)
	spendKey := decoded[1:33]
	viewKey := decoded[33:65]

	// Combine spend and view keys as "public key"
	publicKey := append(spendKey, viewKey...)

	return &AddressInfo{
		Address:   address,
		PublicKey: publicKey,
		ChainID:   ChainMonero,
		Type:      AddressTypeBase58,
		Version:   decoded[0],
	}, nil
}

// keccak256 computes Keccak-256 hash
func keccak256(data []byte) []byte {
	h := sha3.NewLegacyKeccak256()
	h.Write(data)
	return h.Sum(nil)
}

// Monero Base58 alphabet (same as Bitcoin but different encoding)
const moneroBase58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// moneroBase58Encode encodes data using Monero's Base58 variant
// Monero encodes in 8-byte blocks
func moneroBase58Encode(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	result := ""
	fullBlockCount := len(data) / 8
	lastBlockSize := len(data) % 8

	// Encode full 8-byte blocks
	for i := 0; i < fullBlockCount; i++ {
		block := data[i*8 : (i+1)*8]
		encoded := encodeBlock(block)
		// Full blocks encode to 11 characters
		result += padLeft(encoded, 11)
	}

	// Encode last partial block
	if lastBlockSize > 0 {
		block := data[fullBlockCount*8:]
		encoded := encodeBlock(block)
		// Partial block encoding size
		encSize := getEncodedBlockSize(lastBlockSize)
		result += padLeft(encoded, encSize)
	}

	return result
}

// encodeBlock encodes a block of bytes to base58
func encodeBlock(block []byte) string {
	// Convert block to big integer
	var num uint64
	for _, b := range block {
		num = num*256 + uint64(b)
	}

	if num == 0 {
		return "1"
	}

	result := ""
	for num > 0 {
		result = string(moneroBase58Alphabet[num%58]) + result
		num /= 58
	}

	return result
}

// padLeft pads string with '1' (base58 zero) on the left
func padLeft(s string, length int) string {
	for len(s) < length {
		s = "1" + s
	}
	return s
}

// getEncodedBlockSize returns the encoded size for a given input block size
func getEncodedBlockSize(blockSize int) int {
	sizes := []int{0, 2, 3, 5, 6, 7, 9, 10, 11}
	if blockSize < len(sizes) {
		return sizes[blockSize]
	}
	return 11
}

// moneroBase58Decode decodes a Monero Base58 string
func moneroBase58Decode(str string) ([]byte, error) {
	if len(str) == 0 {
		return []byte{}, nil
	}

	// Build reverse lookup
	alphabet := make(map[byte]uint64)
	for i := 0; i < 58; i++ {
		alphabet[moneroBase58Alphabet[i]] = uint64(i)
	}

	result := []byte{}

	// Process in 11-character blocks (except possibly the last)
	fullBlockCount := len(str) / 11
	lastBlockSize := len(str) % 11

	for i := 0; i < fullBlockCount; i++ {
		block := str[i*11 : (i+1)*11]
		decoded, err := decodeBlock(block, alphabet)
		if err != nil {
			return nil, err
		}
		// Full blocks decode to 8 bytes
		result = append(result, padBytes(decoded, 8)...)
	}

	if lastBlockSize > 0 {
		block := str[fullBlockCount*11:]
		decoded, err := decodeBlock(block, alphabet)
		if err != nil {
			return nil, err
		}
		// Get decoded size for this block
		decodedSize := getDecodedBlockSize(lastBlockSize)
		result = append(result, padBytes(decoded, decodedSize)...)
	}

	return result, nil
}

// decodeBlock decodes a base58 block
func decodeBlock(block string, alphabet map[byte]uint64) ([]byte, error) {
	var num uint64
	for i := 0; i < len(block); i++ {
		val, ok := alphabet[block[i]]
		if !ok {
			return nil, fmt.Errorf("invalid character: %c", block[i])
		}
		num = num*58 + val
	}

	// Convert to bytes
	var result []byte
	for num > 0 {
		result = append([]byte{byte(num & 0xFF)}, result...)
		num >>= 8
	}

	if len(result) == 0 {
		return []byte{0}, nil
	}

	return result, nil
}

// padBytes pads or truncates bytes to specified length
func padBytes(data []byte, length int) []byte {
	if len(data) == length {
		return data
	}
	if len(data) > length {
		return data[len(data)-length:]
	}
	result := make([]byte, length)
	copy(result[length-len(data):], data)
	return result
}

// getDecodedBlockSize returns the decoded size for a given encoded block size
func getDecodedBlockSize(encodedSize int) int {
	sizes := map[int]int{2: 1, 3: 2, 5: 3, 6: 4, 7: 5, 9: 6, 10: 7, 11: 8}
	if size, ok := sizes[encodedSize]; ok {
		return size
	}
	return 0
}
