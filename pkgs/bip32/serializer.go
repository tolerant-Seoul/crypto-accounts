package bip32

import (
	"bytes"
	"encoding/binary"

	"github.com/study/crypto-accounts/pkgs/crypto/encoding"
)

const (
	// SerializedKeyLength is the length of a serialized extended key (78 bytes).
	SerializedKeyLength = 78
)

// Serialize serializes the extended key to a 78-byte sequence.
// Format: 4 bytes version || 1 byte depth || 4 bytes fingerprint ||
//
//	4 bytes child index || 32 bytes chain code || 33 bytes key
func (k *ExtendedKey) Serialize() []byte {
	var buf bytes.Buffer

	// 4 bytes: version
	version := k.getVersion()
	verBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(verBytes, version)
	buf.Write(verBytes)

	// 1 byte: depth
	buf.WriteByte(k.depth)

	// 4 bytes: parent fingerprint
	buf.Write(k.parentFP)

	// 4 bytes: child index
	indexBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(indexBytes, k.childIndex)
	buf.Write(indexBytes)

	// 32 bytes: chain code
	buf.Write(k.chainCode)

	// 33 bytes: key data
	buf.Write(k.key)

	return buf.Bytes()
}

// String returns the Base58Check encoded extended key.
func (k *ExtendedKey) String() string {
	return encoding.Base58CheckEncode(k.Serialize())
}

// getVersion returns the appropriate version bytes based on network and key type.
func (k *ExtendedKey) getVersion() uint32 {
	if k.isPrivate {
		return k.network.PrivateKeyID
	}
	return k.network.PublicKeyID
}

// ParseExtendedKey parses a Base58Check encoded extended key string.
func ParseExtendedKey(encoded string) (*ExtendedKey, error) {
	decoded, err := encoding.Base58CheckDecode(encoded)
	if err != nil {
		return nil, err
	}
	return DeserializeExtendedKey(decoded)
}

// DeserializeExtendedKey deserializes a 78-byte extended key.
func DeserializeExtendedKey(data []byte) (*ExtendedKey, error) {
	if len(data) != SerializedKeyLength {
		return nil, ErrInvalidSerializedKey
	}

	version := binary.BigEndian.Uint32(data[0:4])
	depth := data[4]
	parentFP := data[5:9]
	childIndex := binary.BigEndian.Uint32(data[9:13])
	chainCode := data[13:45]
	key := data[45:78]

	// Determine if private key and network
	isPrivate := IsPrivateVersion(version)
	network := NetworkFromVersion(version)
	if network == nil {
		network = DefaultNetwork
	}

	return &ExtendedKey{
		key:        copyBytes(key),
		chainCode:  copyBytes(chainCode),
		depth:      depth,
		parentFP:   copyBytes(parentFP),
		childIndex: childIndex,
		network:    network,
		isPrivate:  isPrivate,
	}, nil
}
