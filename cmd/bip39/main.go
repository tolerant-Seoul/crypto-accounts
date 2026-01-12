// BIP-39 CLI tool for testing mnemonic generation and seed derivation
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/study/crypto-accounts/pkgs/bip32"
	"github.com/study/crypto-accounts/pkgs/bip39"
)

const usage = `BIP-39 Mnemonic CLI Tool

Usage:
  bip39 <command> [options]

Commands:
  generate    Generate new mnemonic phrase
  validate    Validate mnemonic phrase
  seed        Generate seed from mnemonic
  entropy     Convert between entropy and mnemonic

Examples:
  # Generate 12-word mnemonic
  bip39 generate

  # Generate 24-word mnemonic
  bip39 generate --words 24

  # Validate mnemonic
  bip39 validate --mnemonic "abandon abandon ... about"

  # Generate seed from mnemonic
  bip39 seed --mnemonic "abandon abandon ... about"

  # Generate seed with passphrase
  bip39 seed --mnemonic "abandon abandon ... about" --passphrase "TREZOR"

  # Convert entropy to mnemonic
  bip39 entropy --hex 00000000000000000000000000000000
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
	case "seed":
		cmdSeed(os.Args[2:])
	case "entropy":
		cmdEntropy(os.Args[2:])
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
	words := fs.Int("words", 12, "Number of words (12, 15, 18, 21, or 24)")
	passphrase := fs.String("passphrase", "", "Optional passphrase for seed generation")
	fs.Parse(args)

	// Map word count to entropy bits
	wordToBits := map[int]int{
		12: 128,
		15: 160,
		18: 192,
		21: 224,
		24: 256,
	}

	bits, ok := wordToBits[*words]
	if !ok {
		fmt.Printf("Error: invalid word count %d. Must be 12, 15, 18, 21, or 24\n", *words)
		os.Exit(1)
	}

	entropy, err := bip39.GenerateEntropy(bits)
	if err != nil {
		fmt.Printf("Error: failed to generate entropy: %v\n", err)
		os.Exit(1)
	}

	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		fmt.Printf("Error: failed to generate mnemonic: %v\n", err)
		os.Exit(1)
	}

	seed := bip39.NewSeed(mnemonic, *passphrase)

	fmt.Println("=== Generated Mnemonic ===")
	fmt.Printf("Words:      %d\n", *words)
	fmt.Printf("Entropy:    %x\n", entropy)
	fmt.Println()
	fmt.Println("Mnemonic:")
	printMnemonic(mnemonic)
	fmt.Println()
	fmt.Printf("Seed:       %x\n", seed)

	if *passphrase != "" {
		fmt.Printf("Passphrase: %s\n", *passphrase)
	}

	// Show master key
	fmt.Println()
	fmt.Println("=== BIP-32 Master Key ===")
	master, err := bip32.NewMasterKey(seed)
	if err != nil {
		fmt.Printf("Error: failed to generate master key: %v\n", err)
		return
	}
	fmt.Printf("xprv: %s\n", master.String())
	pub, _ := master.Neuter()
	fmt.Printf("xpub: %s\n", pub.String())
}

func cmdValidate(args []string) {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	mnemonic := fs.String("mnemonic", "", "Mnemonic phrase to validate")
	fs.Parse(args)

	if *mnemonic == "" {
		fmt.Println("Error: --mnemonic is required")
		fmt.Println("\nUsage: bip39 validate --mnemonic \"word1 word2 ...\"")
		os.Exit(1)
	}

	if bip39.ValidateMnemonic(*mnemonic) {
		words := strings.Fields(*mnemonic)
		fmt.Println("=== Mnemonic Valid ===")
		fmt.Printf("Words: %d\n", len(words))
		fmt.Println()
		printMnemonic(*mnemonic)
	} else {
		fmt.Println("=== Mnemonic Invalid ===")
		_, err := bip39.MnemonicToEntropy(*mnemonic)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
		}
		os.Exit(1)
	}
}

func cmdSeed(args []string) {
	fs := flag.NewFlagSet("seed", flag.ExitOnError)
	mnemonic := fs.String("mnemonic", "", "Mnemonic phrase")
	passphrase := fs.String("passphrase", "", "Optional passphrase")
	fs.Parse(args)

	if *mnemonic == "" {
		fmt.Println("Error: --mnemonic is required")
		fmt.Println("\nUsage: bip39 seed --mnemonic \"word1 word2 ...\" [--passphrase \"...\"]")
		os.Exit(1)
	}

	if !bip39.ValidateMnemonic(*mnemonic) {
		fmt.Println("Error: invalid mnemonic")
		os.Exit(1)
	}

	seed := bip39.NewSeed(*mnemonic, *passphrase)
	entropy, _ := bip39.MnemonicToEntropy(*mnemonic)

	fmt.Println("=== Seed Generation ===")
	fmt.Println()
	fmt.Println("Mnemonic:")
	printMnemonic(*mnemonic)
	fmt.Println()
	if *passphrase != "" {
		fmt.Printf("Passphrase: %s\n", *passphrase)
	} else {
		fmt.Println("Passphrase: (empty)")
	}
	fmt.Printf("Entropy:    %x\n", entropy)
	fmt.Printf("Seed:       %x\n", seed)

	// Show master key
	fmt.Println()
	fmt.Println("=== BIP-32 Master Key ===")
	master, err := bip32.NewMasterKey(seed)
	if err != nil {
		fmt.Printf("Error: failed to generate master key: %v\n", err)
		return
	}
	fmt.Printf("xprv: %s\n", master.String())
	pub, _ := master.Neuter()
	fmt.Printf("xpub: %s\n", pub.String())
}

func cmdEntropy(args []string) {
	fs := flag.NewFlagSet("entropy", flag.ExitOnError)
	hexStr := fs.String("hex", "", "Entropy in hexadecimal")
	mnemonic := fs.String("mnemonic", "", "Mnemonic phrase to convert to entropy")
	fs.Parse(args)

	if *hexStr == "" && *mnemonic == "" {
		fmt.Println("Error: --hex or --mnemonic is required")
		fmt.Println("\nUsage:")
		fmt.Println("  bip39 entropy --hex <entropy_hex>")
		fmt.Println("  bip39 entropy --mnemonic \"word1 word2 ...\"")
		os.Exit(1)
	}

	if *hexStr != "" {
		// Convert entropy to mnemonic
		entropy, err := hex.DecodeString(*hexStr)
		if err != nil {
			fmt.Printf("Error: invalid hex: %v\n", err)
			os.Exit(1)
		}

		mnemonic, err := bip39.NewMnemonic(entropy)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("=== Entropy to Mnemonic ===")
		fmt.Printf("Entropy (%d bits): %x\n", len(entropy)*8, entropy)
		fmt.Println()
		fmt.Println("Mnemonic:")
		printMnemonic(mnemonic)
	} else {
		// Convert mnemonic to entropy
		entropy, err := bip39.MnemonicToEntropy(*mnemonic)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("=== Mnemonic to Entropy ===")
		fmt.Println("Mnemonic:")
		printMnemonic(*mnemonic)
		fmt.Println()
		fmt.Printf("Entropy (%d bits): %x\n", len(entropy)*8, entropy)
	}
}

func printMnemonic(mnemonic string) {
	words := strings.Fields(mnemonic)
	for i, word := range words {
		fmt.Printf("  %2d. %s\n", i+1, word)
	}
}
