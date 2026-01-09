package bip32

import (
	"encoding/binary"

	"github.com/study/crypto-accounts/pkgs/crypto/hash"
	"github.com/study/crypto-accounts/pkgs/crypto/secp256k1"
)

// Child derives a child extended key at the given index.
// For hardened derivation, use index >= HardenedKeyStart (0x80000000).
// Public keys can only derive unhardened children.
func (k *ExtendedKey) Child(index uint32) (Key, error) {
	isHardened := IsHardened(index)

	// Cannot derive hardened child from public key
	if !k.isPrivate && isHardened {
		return nil, ErrHardenedFromPublic
	}

	// Prepare data for HMAC
	data := buildChildData(k, index, isHardened)

	// HMAC-SHA512 with chain code as key
	I := hash.HMACSHA512(k.chainCode, data)
	IL := I[:32]
	IR := I[32:]

	// Validate IL
	if !secp256k1.IsValidPrivateKey(IL) {
		return nil, ErrDerivationFailed
	}

	childKey, err := deriveChildKey(k, IL)
	if err != nil {
		return nil, err
	}

	return &ExtendedKey{
		key:        childKey,
		chainCode:  IR,
		depth:      k.depth + 1,
		parentFP:   k.Fingerprint(),
		childIndex: index,
		network:    k.network,
		isPrivate:  k.isPrivate,
	}, nil
}

// buildChildData builds the data for HMAC in child key derivation.
func buildChildData(k *ExtendedKey, index uint32, isHardened bool) []byte {
	data := make([]byte, 37)

	if isHardened {
		// Hardened: 0x00 || ser256(kpar) || ser32(i)
		copy(data, k.key)
	} else {
		// Normal: serP(point(kpar)) || ser32(i)
		copy(data, k.PublicKeyBytes())
	}

	binary.BigEndian.PutUint32(data[33:], index)
	return data
}

// deriveChildKey derives the child key bytes.
func deriveChildKey(k *ExtendedKey, IL []byte) ([]byte, error) {
	if k.isPrivate {
		return derivePrivateChildKey(k.key[1:], IL)
	}
	return derivePublicChildKey(k.key, IL)
}

// derivePrivateChildKey derives a private child key from a private parent.
func derivePrivateChildKey(parentKey, IL []byte) ([]byte, error) {
	// child key = (IL + kpar) mod n
	childKeyBytes := secp256k1.AddPrivateKeys(parentKey, IL)

	if !secp256k1.IsValidPrivateKey(childKeyBytes) {
		return nil, ErrDerivationFailed
	}

	// Add 0x00 prefix
	result := make([]byte, 33)
	result[0] = 0x00
	copy(result[1:], childKeyBytes)

	return result, nil
}

// derivePublicChildKey derives a public child key from a public parent.
func derivePublicChildKey(parentPubKey, IL []byte) ([]byte, error) {
	// child key = point(IL) + Kpar
	parentPoint, err := secp256k1.DecompressPoint(parentPubKey)
	if err != nil {
		return nil, ErrDerivationFailed
	}

	ilPoint := secp256k1.ScalarBaseMult(IL)
	childPoint := secp256k1.Add(ilPoint, parentPoint)

	if childPoint.IsInfinity() {
		return nil, ErrDerivationFailed
	}

	return secp256k1.CompressPoint(childPoint), nil
}

// Neuter returns the public extended key for a private extended key.
func (k *ExtendedKey) Neuter() (Key, error) {
	if !k.isPrivate {
		return k.clone(), nil
	}

	return &ExtendedKey{
		key:        k.PublicKeyBytes(),
		chainCode:  copyBytes(k.chainCode),
		depth:      k.depth,
		parentFP:   copyBytes(k.parentFP),
		childIndex: k.childIndex,
		network:    k.network,
		isPrivate:  false,
	}, nil
}

// clone creates a deep copy of the extended key.
func (k *ExtendedKey) clone() *ExtendedKey {
	return &ExtendedKey{
		key:        copyBytes(k.key),
		chainCode:  copyBytes(k.chainCode),
		depth:      k.depth,
		parentFP:   copyBytes(k.parentFP),
		childIndex: k.childIndex,
		network:    k.network,
		isPrivate:  k.isPrivate,
	}
}

// copyBytes creates a copy of a byte slice.
func copyBytes(src []byte) []byte {
	if src == nil {
		return nil
	}
	dst := make([]byte, len(src))
	copy(dst, src)
	return dst
}
