package bip32

import (
	"fmt"
	"strconv"
	"strings"
)

// DerivationPath represents a BIP-32 derivation path as a sequence of indices.
type DerivationPath []uint32

// ParsePath parses a BIP-32 derivation path string.
// Supports formats:
//   - "m/44'/60'/0'/0/0" (with master prefix)
//   - "44'/60'/0'" (without master prefix)
//
// Hardened indices can use ' or h suffix.
func ParsePath(path string) (DerivationPath, error) {
	path = strings.TrimSpace(path)

	if path == "" || path == "m" || path == "M" {
		return DerivationPath{}, nil
	}

	// Remove 'm/' or 'M/' prefix
	if strings.HasPrefix(path, "m/") || strings.HasPrefix(path, "M/") {
		path = path[2:]
	}

	parts := strings.Split(path, "/")
	result := make(DerivationPath, 0, len(parts))

	for _, part := range parts {
		if part == "" {
			continue
		}

		index, err := parsePathComponent(part)
		if err != nil {
			return nil, err
		}

		result = append(result, index)
	}

	return result, nil
}

// parsePathComponent parses a single path component (e.g., "44'" or "0").
func parsePathComponent(part string) (uint32, error) {
	hardened := false

	if strings.HasSuffix(part, "'") || strings.HasSuffix(part, "h") || strings.HasSuffix(part, "H") {
		hardened = true
		part = part[:len(part)-1]
	}

	index, err := strconv.ParseUint(part, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("%w: invalid index '%s'", ErrInvalidPath, part)
	}

	if hardened && index >= uint64(HardenedKeyStart) {
		return 0, fmt.Errorf("%w: index too large for hardened derivation", ErrInvalidPath)
	}

	idx := uint32(index)
	if hardened {
		idx += HardenedKeyStart
	}

	return idx, nil
}

// String returns the string representation of the derivation path.
func (p DerivationPath) String() string {
	if len(p) == 0 {
		return "m"
	}

	parts := make([]string, 0, len(p)+1)
	parts = append(parts, "m")

	for _, idx := range p {
		if IsHardened(idx) {
			parts = append(parts, fmt.Sprintf("%d'", idx-HardenedKeyStart))
		} else {
			parts = append(parts, fmt.Sprintf("%d", idx))
		}
	}

	return strings.Join(parts, "/")
}

// DeriveFromPath derives a child key following the given derivation path.
func (k *ExtendedKey) DeriveFromPath(path DerivationPath) (*ExtendedKey, error) {
	current := k

	for _, idx := range path {
		child, err := current.Child(idx)
		if err != nil {
			return nil, fmt.Errorf("derivation failed at index %d: %w", idx, err)
		}
		current = child.(*ExtendedKey)
	}

	return current, nil
}

// DeriveFromPathString derives a child key following the given path string.
func (k *ExtendedKey) DeriveFromPathString(pathStr string) (*ExtendedKey, error) {
	path, err := ParsePath(pathStr)
	if err != nil {
		return nil, err
	}
	return k.DeriveFromPath(path)
}

// MustParsePath parses a path string and panics on error.
func MustParsePath(path string) DerivationPath {
	p, err := ParsePath(path)
	if err != nil {
		panic(err)
	}
	return p
}

// Common derivation paths
var (
	// PathBIP44Bitcoin is the BIP-44 path for Bitcoin mainnet.
	PathBIP44Bitcoin = MustParsePath("m/44'/0'/0'/0/0")

	// PathBIP44Ethereum is the BIP-44 path for Ethereum.
	PathBIP44Ethereum = MustParsePath("m/44'/60'/0'/0/0")

	// PathBIP49Bitcoin is the BIP-49 path for Bitcoin SegWit.
	PathBIP49Bitcoin = MustParsePath("m/49'/0'/0'/0/0")

	// PathBIP84Bitcoin is the BIP-84 path for Bitcoin Native SegWit.
	PathBIP84Bitcoin = MustParsePath("m/84'/0'/0'/0/0")
)
