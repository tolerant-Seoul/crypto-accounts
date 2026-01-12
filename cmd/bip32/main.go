// BIP-32 CLI tool for testing HD wallet key derivation
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/study/crypto-accounts/pkgs/bip32"
)

const usage = `BIP-32 HD Wallet CLI Tool

Usage:
  bip32 <command> [options]

Commands:
  generate    Generate master key from seed
  derive      Derive child key from extended key
  parse       Parse and display extended key info
  info        Show key details

Examples:
  # Generate master key from hex seed
  bip32 generate --seed 000102030405060708090a0b0c0d0e0f

  # Derive child key using path
  bip32 derive --key "xprv9s21ZrQH143K..." --path "m/44'/0'/0'/0/0"

  # Parse extended key
  bip32 parse --key "xprv9s21ZrQH143K..."

  # Show key info with public key
  bip32 info --key "xprv9s21ZrQH143K..."
`

func main() {
	if len(os.Args) < 2 {
		fmt.Print(usage)
		os.Exit(1)
	}

	switch os.Args[1] {
	case "generate":
		cmdGenerate(os.Args[2:])
	case "derive":
		cmdDerive(os.Args[2:])
	case "parse":
		cmdParse(os.Args[2:])
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
	seedHex := fs.String("seed", "", "Seed in hexadecimal (32-64 bytes recommended)")
	network := fs.String("network", "mainnet", "Network: mainnet or testnet")
	fs.Parse(args)

	if *seedHex == "" {
		fmt.Println("Error: --seed is required")
		fmt.Println("\nUsage: bip32 generate --seed <hex>")
		fmt.Println("\nExample:")
		fmt.Println("  bip32 generate --seed 000102030405060708090a0b0c0d0e0f")
		os.Exit(1)
	}

	seed, err := hex.DecodeString(*seedHex)
	if err != nil {
		fmt.Printf("Error: invalid hex seed: %v\n", err)
		os.Exit(1)
	}

	var net *bip32.Network
	switch strings.ToLower(*network) {
	case "mainnet", "main":
		net = bip32.MainNet
	case "testnet", "test":
		net = bip32.TestNet
	default:
		fmt.Printf("Error: unknown network: %s\n", *network)
		os.Exit(1)
	}

	master, err := bip32.NewMasterKeyWithNetwork(seed, net)
	if err != nil {
		fmt.Printf("Error: failed to generate master key: %v\n", err)
		os.Exit(1)
	}

	pub, _ := master.Neuter()

	fmt.Println("=== Master Key Generated ===")
	fmt.Printf("Network:     %s\n", net.Name)
	fmt.Printf("Seed:        %s\n", *seedHex)
	fmt.Println()
	fmt.Printf("xprv:        %s\n", master.String())
	fmt.Printf("xpub:        %s\n", pub.String())
	fmt.Println()
	fmt.Printf("Private Key: %x\n", master.PrivateKeyBytes())
	fmt.Printf("Public Key:  %x\n", master.PublicKeyBytes())
	fmt.Printf("Chain Code:  %x\n", master.ChainCode())
}

func cmdDerive(args []string) {
	fs := flag.NewFlagSet("derive", flag.ExitOnError)
	keyStr := fs.String("key", "", "Extended key (xprv/xpub)")
	path := fs.String("path", "", "Derivation path (e.g., m/44'/0'/0'/0/0)")
	index := fs.Int("index", -1, "Single child index (alternative to path)")
	hardened := fs.Bool("hardened", false, "Use hardened derivation for --index")
	fs.Parse(args)

	if *keyStr == "" {
		fmt.Println("Error: --key is required")
		fmt.Println("\nUsage: bip32 derive --key <xprv/xpub> --path <path>")
		fmt.Println("       bip32 derive --key <xprv/xpub> --index <n> [--hardened]")
		os.Exit(1)
	}

	if *path == "" && *index < 0 {
		fmt.Println("Error: --path or --index is required")
		os.Exit(1)
	}

	key, err := bip32.ParseExtendedKey(*keyStr)
	if err != nil {
		fmt.Printf("Error: failed to parse key: %v\n", err)
		os.Exit(1)
	}

	var child *bip32.ExtendedKey

	if *path != "" {
		child, err = key.DeriveFromPathString(*path)
		if err != nil {
			fmt.Printf("Error: derivation failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("=== Derived Key: %s ===\n", *path)
	} else {
		idx := uint32(*index)
		if *hardened {
			idx = bip32.Hardened(idx)
		}
		childKey, err := key.Child(idx)
		if err != nil {
			fmt.Printf("Error: derivation failed: %v\n", err)
			os.Exit(1)
		}
		child = childKey.(*bip32.ExtendedKey)

		pathStr := fmt.Sprintf("%d", *index)
		if *hardened {
			pathStr += "'"
		}
		fmt.Printf("=== Derived Key: %s ===\n", pathStr)
	}

	fmt.Println()
	printKeyInfo(child)
}

func cmdParse(args []string) {
	fs := flag.NewFlagSet("parse", flag.ExitOnError)
	keyStr := fs.String("key", "", "Extended key to parse")
	fs.Parse(args)

	if *keyStr == "" {
		fmt.Println("Error: --key is required")
		fmt.Println("\nUsage: bip32 parse --key <xprv/xpub>")
		os.Exit(1)
	}

	key, err := bip32.ParseExtendedKey(*keyStr)
	if err != nil {
		fmt.Printf("Error: failed to parse key: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("=== Extended Key Info ===")
	fmt.Println()
	printKeyInfo(key)
}

func cmdInfo(args []string) {
	fs := flag.NewFlagSet("info", flag.ExitOnError)
	keyStr := fs.String("key", "", "Extended key")
	fs.Parse(args)

	if *keyStr == "" {
		fmt.Println("Error: --key is required")
		os.Exit(1)
	}

	key, err := bip32.ParseExtendedKey(*keyStr)
	if err != nil {
		fmt.Printf("Error: failed to parse key: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("=== Key Details ===")
	fmt.Println()
	printKeyInfo(key)

	// Show some derived addresses
	if key.Depth() == 0 {
		fmt.Println()
		fmt.Println("=== Common Derivation Paths ===")
		paths := []struct {
			name string
			path string
		}{
			{"Bitcoin (BIP-44)", "m/44'/0'/0'/0/0"},
			{"Ethereum (BIP-44)", "m/44'/60'/0'/0/0"},
			{"Bitcoin SegWit (BIP-84)", "m/84'/0'/0'/0/0"},
		}

		for _, p := range paths {
			if key.IsPrivate() {
				derived, err := key.DeriveFromPathString(p.path)
				if err != nil {
					continue
				}
				fmt.Printf("\n%s: %s\n", p.name, p.path)
				fmt.Printf("  Private: %x\n", derived.PrivateKeyBytes())
				fmt.Printf("  Public:  %x\n", derived.PublicKeyBytes())
			}
		}
	}
}

func printKeyInfo(key *bip32.ExtendedKey) {
	keyType := "Private"
	if !key.IsPrivate() {
		keyType = "Public"
	}

	fmt.Printf("Type:        %s Extended Key\n", keyType)
	fmt.Printf("Network:     %s\n", key.Network().Name)
	fmt.Printf("Depth:       %d\n", key.Depth())
	fmt.Printf("Child Index: %d", key.ChildIndex())
	if bip32.IsHardened(key.ChildIndex()) && key.ChildIndex() != 0 {
		fmt.Printf(" (hardened: %d')", key.ChildIndex()-bip32.HardenedKeyStart)
	}
	fmt.Println()
	fmt.Printf("Fingerprint: %x\n", key.Fingerprint())
	fmt.Printf("Parent FP:   %x\n", key.ParentFingerprint())
	fmt.Println()

	if key.IsPrivate() {
		fmt.Printf("xprv:        %s\n", key.String())
		pub, _ := key.Neuter()
		fmt.Printf("xpub:        %s\n", pub.String())
		fmt.Println()
		fmt.Printf("Private Key: %x\n", key.PrivateKeyBytes())
	} else {
		fmt.Printf("xpub:        %s\n", key.String())
		fmt.Println()
	}
	fmt.Printf("Public Key:  %x\n", key.PublicKeyBytes())
	fmt.Printf("Chain Code:  %x\n", key.ChainCode())
}
