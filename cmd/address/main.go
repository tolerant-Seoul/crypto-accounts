// Address CLI tool for generating and validating cryptocurrency addresses
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/study/crypto-accounts/pkgs/address"
	"github.com/study/crypto-accounts/pkgs/bip39"
	"github.com/study/crypto-accounts/pkgs/bip44"
	"github.com/study/crypto-accounts/pkgs/crypto/ed25519"
	"github.com/study/crypto-accounts/pkgs/crypto/rsa"
	"github.com/study/crypto-accounts/pkgs/crypto/secp256k1"
)

const usage = `Address Generation CLI Tool

Usage:
  address <command> [options]

Commands:
  generate    Generate address from private key or mnemonic
  validate    Validate an address
  chains      List supported chains
  info        Show chain information

Examples:
  # Generate Bitcoin address from private key
  address generate --chain btc --privkey e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35

  # Generate Ethereum address from private key
  address generate --chain eth --privkey e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35

  # Generate addresses from mnemonic
  address generate --chain eth --mnemonic "abandon abandon ... about" --count 5

  # Generate Arweave address with new RSA key
  address generate --chain ar --generate-rsa

  # Generate Arweave address from JWK file
  address generate --chain ar --jwk wallet.json

  # Validate an address
  address validate --chain btc --address 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2

  # List supported chains
  address chains

  # Show chain info
  address info --chain eth
`

func main() {
	if len(os.Args) < 2 {
		fmt.Print(usage)
		os.Exit(1)
	}

	switch os.Args[1] {
	case "generate":
		cmdGenerate(os.Args[2:])
	case "validate":
		cmdValidate(os.Args[2:])
	case "chains":
		cmdChains(os.Args[2:])
	case "info":
		cmdInfo(os.Args[2:])
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Printf("Unknown command: %s\n\n", os.Args[1])
		fmt.Print(usage)
		os.Exit(1)
	}
}

func cmdGenerate(args []string) {
	fs := flag.NewFlagSet("generate", flag.ExitOnError)
	chain := fs.String("chain", "", "Chain ID (btc, eth, sol, etc.)")
	privkey := fs.String("privkey", "", "Private key in hex (32 bytes)")
	pubkey := fs.String("pubkey", "", "Public key in hex (advanced)")
	mnemonic := fs.String("mnemonic", "", "BIP-39 mnemonic phrase")
	passphrase := fs.String("passphrase", "", "BIP-39 passphrase")
	account := fs.Uint("account", 0, "BIP-44 account index")
	count := fs.Uint("count", 1, "Number of addresses to generate")
	format := fs.String("format", "", "Address format (e.g., p2pkh, p2sh, bech32 for Bitcoin)")
	// RSA options for Arweave
	generateRSA := fs.Bool("generate-rsa", false, "Generate new RSA key (for Arweave)")
	jwkFile := fs.String("jwk", "", "Path to JWK file (for Arweave)")
	saveJWK := fs.String("save-jwk", "", "Save generated RSA key to JWK file")
	fs.Parse(args)

	if *chain == "" {
		fmt.Println("Error: --chain is required")
		os.Exit(1)
	}

	chainID := address.ChainID(strings.ToLower(*chain))

	// RSA key generation for Arweave
	if *generateRSA {
		if chainID != address.ChainArweave {
			fmt.Println("Error: --generate-rsa is only supported for Arweave (ar)")
			os.Exit(1)
		}
		generateArweaveWithNewRSA(*saveJWK)
		return
	}

	// Generate from JWK file (for Arweave)
	if *jwkFile != "" {
		if chainID != address.ChainArweave {
			fmt.Println("Error: --jwk is only supported for Arweave (ar)")
			os.Exit(1)
		}
		generateArweaveFromJWK(*jwkFile)
		return
	}

	// Generate from private key (recommended)
	if *privkey != "" {
		generateFromPrivkey(chainID, *privkey, *format)
		return
	}

	// Generate from mnemonic
	if *mnemonic != "" {
		generateFromMnemonic(chainID, *mnemonic, *passphrase, uint32(*account), uint32(*count), *format)
		return
	}

	// Generate from public key (advanced)
	if *pubkey != "" {
		generateFromPubkey(chainID, *pubkey, *format)
		return
	}

	// Special message for Arweave
	if chainID == address.ChainArweave {
		fmt.Println("Error: Arweave requires RSA keys. Use --generate-rsa or --jwk")
		fmt.Println("  Example: address generate --chain ar --generate-rsa")
		fmt.Println("  Example: address generate --chain ar --jwk wallet.json")
		os.Exit(1)
	}

	fmt.Println("Error: --privkey, --mnemonic, or --pubkey is required")
	os.Exit(1)
}

func generateFromPubkey(chainID address.ChainID, pubkeyHex, format string) {
	pubkey, err := hex.DecodeString(pubkeyHex)
	if err != nil {
		fmt.Printf("Error: invalid public key hex: %v\n", err)
		os.Exit(1)
	}

	// Handle special formats for Bitcoin
	if chainID == address.ChainBitcoin {
		btc := address.NewBitcoinAddress(false)
		switch strings.ToLower(format) {
		case "p2pkh", "legacy", "":
			addr, err := btc.P2PKH(pubkey)
			if err != nil {
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("P2PKH Address: %s\n", addr)
		case "bech32", "segwit", "p2wpkh":
			addr, err := btc.P2WPKH(pubkey)
			if err != nil {
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("Bech32 Address: %s\n", addr)
		default:
			fmt.Printf("Unknown format: %s\n", format)
			os.Exit(1)
		}
		return
	}

	// Default generation
	addr, err := address.Generate(chainID, pubkey)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Address: %s\n", addr)
}

func generateFromMnemonic(chainID address.ChainID, mnemonic, passphrase string, accountIdx, count uint32, format string) {
	if !bip39.ValidateMnemonic(mnemonic) {
		fmt.Println("Error: invalid mnemonic")
		os.Exit(1)
	}

	// Check if this is an Ed25519 chain
	if isEd25519Chain(chainID) {
		generateFromMnemonicEd25519(chainID, mnemonic, passphrase, accountIdx, count)
		return
	}

	// secp256k1 chains use BIP-44
	generateFromMnemonicSecp256k1(chainID, mnemonic, passphrase, accountIdx, count, format)
}

// generateFromMnemonicEd25519 generates addresses for Ed25519 chains using SLIP-10
func generateFromMnemonicEd25519(chainID address.ChainID, mnemonic, passphrase string, accountIdx, count uint32) {
	// Generate seed from mnemonic
	seed := bip39.NewSeed(mnemonic, passphrase)

	// Get coin type for the chain
	coinType := chainToCoinTypeEd25519(chainID)

	fmt.Printf("=== %s Addresses (Ed25519/SLIP-10) ===\n", strings.ToUpper(string(chainID)))
	fmt.Printf("Account: %d\n", accountIdx)
	fmt.Printf("Curve: Ed25519\n\n")

	for i := uint32(0); i < count; i++ {
		// SLIP-10 path: m/44'/coin_type'/account'/change'/address_index'
		// All components are hardened for Ed25519
		path := []uint32{
			0x80000000 + 44,           // 44' (purpose)
			0x80000000 + coinType,     // coin_type'
			0x80000000 + accountIdx,   // account'
			0x80000000 + 0,            // change' (0 = external)
			0x80000000 + i,            // address_index'
		}

		privkey, pubkey, err := ed25519.DeriveKeyFromPath(seed, path)
		if err != nil {
			fmt.Printf("Error deriving key: %v\n", err)
			continue
		}

		addr, err := address.Generate(chainID, pubkey)
		if err != nil {
			fmt.Printf("Error generating address: %v\n", err)
			continue
		}

		pathStr := fmt.Sprintf("m/44'/%d'/%d'/0'/%d'", coinType, accountIdx, i)
		fmt.Printf("Path: %s\n", pathStr)
		fmt.Printf("  Address: %s\n", addr)
		fmt.Printf("  Public Key: %s\n", hex.EncodeToString(pubkey))
		fmt.Printf("  Private Key: %s\n\n", hex.EncodeToString(privkey))
	}
}

// generateFromMnemonicSecp256k1 generates addresses for secp256k1 chains using BIP-44
func generateFromMnemonicSecp256k1(chainID address.ChainID, mnemonic, passphrase string, accountIdx, count uint32, format string) {
	wallet, err := bip44.NewWalletFromMnemonic(mnemonic, passphrase)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	// Map chain ID to BIP-44 coin type
	coinType := chainToCoinType(chainID)
	if coinType == 0 && chainID != address.ChainBitcoin {
		fmt.Printf("Error: chain %s not supported for BIP-44 derivation\n", chainID)
		os.Exit(1)
	}

	fmt.Printf("=== %s Addresses (secp256k1/BIP-44) ===\n", strings.ToUpper(string(chainID)))
	fmt.Printf("Account: %d\n", accountIdx)
	fmt.Printf("Curve: secp256k1\n\n")

	for i := uint32(0); i < count; i++ {
		path := bip44.NewPath(coinType, accountIdx, 0, i)
		key, err := wallet.DeriveKey(path)
		if err != nil {
			fmt.Printf("Error deriving key: %v\n", err)
			continue
		}

		// Get public key based on chain type
		var pubkey []byte
		var addr string

		switch chainID {
		case address.ChainEthereum, address.ChainBSC, address.ChainPolygon,
			address.ChainFantom, address.ChainOptimism, address.ChainArbitrum,
			address.ChainVeChain, address.ChainTheta, address.ChainTron:
			// EVM chains need uncompressed public key
			compressedKey := key.PublicKeyBytes()
			pubkey, err = decompressPublicKey(compressedKey)
			if err != nil {
				fmt.Printf("Error decompressing public key: %v\n", err)
				continue
			}
			addr, err = address.Generate(chainID, pubkey)

		default:
			// Most chains use compressed public key
			pubkey = key.PublicKeyBytes()
			addr, err = address.Generate(chainID, pubkey)
		}

		if err != nil {
			fmt.Printf("Error generating address: %v\n", err)
			continue
		}

		fmt.Printf("Path: %s\n", path.String())
		fmt.Printf("  Address: %s\n", addr)
		fmt.Printf("  Public Key: %s\n\n", hex.EncodeToString(pubkey))
	}
}

// chainToCoinTypeEd25519 returns the coin type for Ed25519 chains
func chainToCoinTypeEd25519(chainID address.ChainID) uint32 {
	switch chainID {
	case address.ChainSolana:
		return 501
	case address.ChainStellar:
		return 148
	case address.ChainAlgorand:
		return 283
	case address.ChainNEAR:
		return 397
	case address.ChainAptos:
		return 637
	case address.ChainSui:
		return 784
	case address.ChainCardano:
		return 1815
	default:
		return 0
	}
}

func cmdValidate(args []string) {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	chain := fs.String("chain", "", "Chain ID (btc, eth, sol, etc.)")
	addr := fs.String("address", "", "Address to validate")
	fs.Parse(args)

	if *chain == "" || *addr == "" {
		fmt.Println("Error: --chain and --address are required")
		os.Exit(1)
	}

	chainID := address.ChainID(strings.ToLower(*chain))

	valid := address.Validate(chainID, *addr)
	if valid {
		fmt.Printf("✓ Valid %s address\n", strings.ToUpper(string(chainID)))
	} else {
		fmt.Printf("✗ Invalid %s address\n", strings.ToUpper(string(chainID)))
		os.Exit(1)
	}
}

func cmdChains(args []string) {
	infos := address.ListAllChainInfo()

	// Sort by chain ID
	sort.Slice(infos, func(i, j int) bool {
		return infos[i].ID < infos[j].ID
	})

	fmt.Println("=== Supported Chains ===")
	fmt.Println()
	fmt.Printf("%-8s %-20s %-8s %-20s\n", "ID", "Name", "Symbol", "Address Type")
	fmt.Println(strings.Repeat("-", 60))

	for _, info := range infos {
		fmt.Printf("%-8s %-20s %-8s %-20s\n", info.ID, info.Name, info.Symbol, info.AddressType)
	}
	fmt.Println()
}

func cmdInfo(args []string) {
	fs := flag.NewFlagSet("info", flag.ExitOnError)
	chain := fs.String("chain", "", "Chain ID")
	fs.Parse(args)

	if *chain == "" {
		fmt.Println("Error: --chain is required")
		os.Exit(1)
	}

	chainID := address.ChainID(strings.ToLower(*chain))
	info := address.GetChainInfo(chainID)

	if info == nil {
		fmt.Printf("Unknown chain: %s\n", *chain)
		os.Exit(1)
	}

	fmt.Printf("=== %s ===\n", info.Name)
	fmt.Println()
	fmt.Printf("Chain ID:     %s\n", info.ID)
	fmt.Printf("Symbol:       %s\n", info.Symbol)
	fmt.Printf("Address Type: %s\n", info.AddressType)
	fmt.Printf("Description:  %s\n", info.Description)
	fmt.Println()
}

// decompressPublicKey decompresses a secp256k1 public key
func decompressPublicKey(compressed []byte) ([]byte, error) {
	if len(compressed) != 33 {
		return nil, fmt.Errorf("invalid compressed public key length")
	}

	// Use our secp256k1 library to decompress
	point, err := secp256k1.DecompressPoint(compressed)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress public key: %v", err)
	}

	return secp256k1.SerializeUncompressed(point), nil
}

// isEd25519Chain returns true if the chain uses Ed25519 curve
func isEd25519Chain(chainID address.ChainID) bool {
	switch chainID {
	case address.ChainSolana, address.ChainStellar, address.ChainAlgorand,
		address.ChainNEAR, address.ChainAptos, address.ChainSui, address.ChainCardano:
		return true
	default:
		return false
	}
}

// generateFromPrivkey generates an address from a private key
func generateFromPrivkey(chainID address.ChainID, privkeyHex, format string) {
	privkey, err := hex.DecodeString(privkeyHex)
	if err != nil {
		fmt.Printf("Error: invalid private key hex: %v\n", err)
		os.Exit(1)
	}

	if len(privkey) != 32 {
		fmt.Printf("Error: private key must be 32 bytes, got %d bytes\n", len(privkey))
		os.Exit(1)
	}

	// Check if this is an Ed25519 chain
	if isEd25519Chain(chainID) {
		generateFromPrivkeyEd25519(chainID, privkey)
		return
	}

	// secp256k1 chains
	generateFromPrivkeySecp256k1(chainID, privkey, format)
}

// generateFromPrivkeyEd25519 generates address for Ed25519 chains
func generateFromPrivkeyEd25519(chainID address.ChainID, privkey []byte) {
	// Derive Ed25519 public key from private key
	pubkey, err := ed25519.PrivateKeyToPublicKey(privkey)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Private Key: %s\n", hex.EncodeToString(privkey))
	fmt.Printf("Public Key (Ed25519): %s\n", hex.EncodeToString(pubkey))
	fmt.Printf("Curve: Ed25519\n")
	fmt.Println()

	addr, err := address.Generate(chainID, pubkey)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Address: %s\n", addr)
}

// generateFromPrivkeySecp256k1 generates address for secp256k1 chains
func generateFromPrivkeySecp256k1(chainID address.ChainID, privkey []byte, format string) {
	// Derive public key from private key
	point := secp256k1.PrivateKeyToPublicKey(privkey)
	compressedPubkey := secp256k1.CompressPoint(point)
	uncompressedPubkey := secp256k1.SerializeUncompressed(point)

	fmt.Printf("Private Key: %s\n", hex.EncodeToString(privkey))
	fmt.Printf("Public Key (compressed): %s\n", hex.EncodeToString(compressedPubkey))
	fmt.Printf("Public Key (uncompressed): %s\n", hex.EncodeToString(uncompressedPubkey))
	fmt.Printf("Curve: secp256k1\n")
	fmt.Println()

	// Handle special formats for Bitcoin
	if chainID == address.ChainBitcoin {
		btc := address.NewBitcoinAddress(false)
		switch strings.ToLower(format) {
		case "p2pkh", "legacy", "":
			addr, err := btc.P2PKH(compressedPubkey)
			if err != nil {
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("P2PKH Address: %s\n", addr)
		case "bech32", "segwit", "p2wpkh":
			addr, err := btc.P2WPKH(compressedPubkey)
			if err != nil {
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("Bech32 Address: %s\n", addr)
		case "all":
			// Generate all address types
			p2pkh, _ := btc.P2PKH(compressedPubkey)
			p2wpkh, _ := btc.P2WPKH(compressedPubkey)
			fmt.Printf("P2PKH Address:  %s\n", p2pkh)
			fmt.Printf("Bech32 Address: %s\n", p2wpkh)
		default:
			fmt.Printf("Unknown format: %s\n", format)
			os.Exit(1)
		}
		return
	}

	// Handle special chain cases
	var pubkey []byte
	var addr string
	var err error

	switch chainID {
	case address.ChainEthereum, address.ChainBSC, address.ChainPolygon,
		address.ChainFantom, address.ChainOptimism, address.ChainArbitrum,
		address.ChainVeChain, address.ChainTheta, address.ChainEthereumClassic,
		address.ChainTron:
		// Use uncompressed public key for EVM/TRON chains
		pubkey = uncompressedPubkey
		addr, err = address.Generate(chainID, pubkey)

	case address.ChainTezos:
		// Tezos with secp256k1 generates tz2 address
		tezos := address.NewTezosAddressWithKeyType(address.TezosKeySecp256k1)
		addr, err = tezos.GenerateTz2(compressedPubkey)
		pubkey = compressedPubkey

	case address.ChainFilecoin:
		// Filecoin uses 65-byte uncompressed public key (0x04 + x + y)
		// uncompressedPubkey from secp256k1.SerializeUncompressed already includes 0x04 prefix
		pubkey = uncompressedPubkey
		addr, err = address.Generate(chainID, pubkey)

	case address.ChainMonero:
		// Monero requires dual keys (spend + view), show warning
		fmt.Println("Note: Monero requires both spend and view public keys (64 bytes total).")
		fmt.Println("      Use --pubkey with 64-byte hex (spend_key || view_key) for proper address generation.")
		fmt.Println("      Generating placeholder address with single key for demonstration:")
		// Generate a placeholder address using the key twice
		dualKey := append(compressedPubkey[:32], compressedPubkey[:32]...)
		if len(dualKey) < 64 {
			dualKey = append(dualKey, make([]byte, 64-len(dualKey))...)
		}
		pubkey = dualKey[:64]
		addr, err = address.Generate(chainID, pubkey)

	default:
		// Most chains use compressed public key
		pubkey = compressedPubkey
		addr, err = address.Generate(chainID, pubkey)
	}

	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Address: %s\n", addr)
}

func chainToCoinType(chainID address.ChainID) bip44.CoinType {
	mapping := map[address.ChainID]bip44.CoinType{
		address.ChainBitcoin:         bip44.CoinTypeBitcoin,
		address.ChainEthereum:        bip44.CoinTypeEthereum,
		address.ChainLitecoin:        bip44.CoinTypeLitecoin,
		address.ChainDogecoin:        bip44.CoinTypeDogecoin,
		address.ChainRipple:          bip44.CoinTypeRipple,
		address.ChainBSC:             bip44.CoinTypeEthereum, // BSC uses ETH coin type
		address.ChainPolygon:         bip44.CoinTypePolygon,
		address.ChainSolana:          bip44.CoinTypeSolana,
		address.ChainTron:            bip44.CoinTypeTron,
		address.ChainCosmos:          bip44.CoinType(118),
		address.ChainStellar:         bip44.CoinTypeStellar,
		address.ChainBitcoinCash:     bip44.CoinTypeBitcoinCash,
		address.ChainAvalanche:       bip44.CoinTypeAvalanche,
		address.ChainBinanceBEP2:     bip44.CoinTypeBinance,
		address.ChainFantom:          bip44.CoinTypeEthereum,
		address.ChainOptimism:        bip44.CoinTypeEthereum,
		address.ChainArbitrum:        bip44.CoinTypeEthereum,
		address.ChainEthereumClassic: bip44.CoinTypeEthereumClassic,
	}

	if coinType, ok := mapping[chainID]; ok {
		return coinType
	}
	return 0
}

// generateArweaveWithNewRSA generates a new RSA key and creates an Arweave address
func generateArweaveWithNewRSA(saveJWKPath string) {
	fmt.Println("Generating new 4096-bit RSA key for Arweave...")
	fmt.Println("(This may take a few seconds)")
	fmt.Println()

	// Generate new RSA key
	key, err := rsa.GenerateArweaveKey()
	if err != nil {
		fmt.Printf("Error generating RSA key: %v\n", err)
		os.Exit(1)
	}

	// Get key info
	info := rsa.GetKeyInfo(&key.PublicKey)
	fmt.Printf("RSA Key Size: %d bits\n", info.BitSize)
	fmt.Printf("Public Exponent: %d\n", info.Exponent)
	fmt.Println()

	// Generate address from modulus
	modulus := rsa.GetModulus(&key.PublicKey)
	addr, err := address.Generate(address.ChainArweave, modulus)
	if err != nil {
		fmt.Printf("Error generating address: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Arweave Address: %s\n", addr)
	fmt.Println()

	// Get owner (Base64URL encoded modulus)
	owner := rsa.GetArweaveOwner(&key.PublicKey)
	fmt.Printf("Owner (for transactions): %s...\n", owner[:64])
	fmt.Println()

	// Convert to JWK
	jwk := rsa.PrivateKeyToJWK(key)
	jwkJSON, err := jwk.ToJSON()
	if err != nil {
		fmt.Printf("Error converting to JWK: %v\n", err)
		os.Exit(1)
	}

	// Save or display JWK
	if saveJWKPath != "" {
		err = os.WriteFile(saveJWKPath, []byte(jwkJSON), 0600)
		if err != nil {
			fmt.Printf("Error saving JWK file: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("JWK saved to: %s\n", saveJWKPath)
		fmt.Println()
		fmt.Println("WARNING: Keep this file secure! It contains your private key.")
	} else {
		fmt.Println("JWK (save this to a file for wallet recovery):")
		fmt.Println("WARNING: This contains your private key - keep it secure!")
		fmt.Println()
		fmt.Println(jwkJSON)
	}
}

// generateArweaveFromJWK generates an Arweave address from a JWK file
func generateArweaveFromJWK(jwkPath string) {
	// Read JWK file
	data, err := os.ReadFile(jwkPath)
	if err != nil {
		fmt.Printf("Error reading JWK file: %v\n", err)
		os.Exit(1)
	}

	// Parse JWK
	key, err := rsa.PrivateKeyFromJWKJSON(string(data))
	if err != nil {
		fmt.Printf("Error parsing JWK: %v\n", err)
		os.Exit(1)
	}

	// Get key info
	info := rsa.GetKeyInfo(&key.PublicKey)
	fmt.Printf("RSA Key Size: %d bits\n", info.BitSize)
	fmt.Printf("Public Exponent: %d\n", info.Exponent)
	fmt.Println()

	// Validate key size
	if err := rsa.ValidateKeySize(&key.PublicKey); err != nil {
		fmt.Printf("Warning: %v\n", err)
	}

	// Generate address from modulus
	modulus := rsa.GetModulus(&key.PublicKey)
	addr, err := address.Generate(address.ChainArweave, modulus)
	if err != nil {
		fmt.Printf("Error generating address: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Arweave Address: %s\n", addr)
	fmt.Println()

	// Get owner (Base64URL encoded modulus)
	owner := rsa.GetArweaveOwner(&key.PublicKey)
	fmt.Printf("Owner (for transactions): %s...\n", owner[:64])
}
