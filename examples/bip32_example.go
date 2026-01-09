// Example usage of the BIP-32 HD Wallet implementation
package main

import (
	"encoding/hex"
	"fmt"
	"log"

	"github.com/study/crypto-accounts/pkgs/bip32"
)

func main() {
	fmt.Println("=== BIP-32 HD Wallet Example ===")
	fmt.Println()

	// 1. Create master key from seed
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	fmt.Printf("Seed: %x\n\n", seed)

	master, err := bip32.NewMasterKey(seed)
	if err != nil {
		log.Fatalf("Failed to create master key: %v", err)
	}

	fmt.Println("--- Master Key ---")
	fmt.Printf("xprv: %s\n", master.String())

	masterPub, _ := master.Neuter()
	fmt.Printf("xpub: %s\n", masterPub.String())
	fmt.Printf("Private Key: %x\n", master.PrivateKeyBytes())
	fmt.Printf("Public Key:  %x\n", master.PublicKeyBytes())
	fmt.Println()

	// 2. Derive using path string
	fmt.Println("--- Derive: m/44'/0'/0'/0/0 (BIP-44 Bitcoin) ---")
	btcKey, err := master.DeriveFromPathString("m/44'/0'/0'/0/0")
	if err != nil {
		log.Fatalf("Failed to derive: %v", err)
	}
	fmt.Printf("xprv: %s\n", btcKey.String())
	fmt.Printf("Private Key: %x\n", btcKey.PrivateKeyBytes())
	fmt.Println()

	// 3. Derive using predefined path
	fmt.Println("--- Derive: m/44'/60'/0'/0/0 (BIP-44 Ethereum) ---")
	ethKey, _ := master.DeriveFromPath(bip32.PathBIP44Ethereum)
	fmt.Printf("xprv: %s\n", ethKey.String())
	fmt.Printf("Private Key: %x\n", ethKey.PrivateKeyBytes())
	fmt.Println()

	// 4. Step-by-step derivation
	fmt.Println("--- Step-by-step Derivation ---")
	child0h, _ := master.Child(bip32.Hardened(0))
	fmt.Printf("m/0':    %s\n", child0h.String())

	child0h1, _ := child0h.(*bip32.ExtendedKey).Child(1)
	fmt.Printf("m/0'/1:  %s\n", child0h1.String())
	fmt.Println()

	// 5. Public key derivation (watch-only wallet)
	fmt.Println("--- Public Key Derivation (Watch-only) ---")
	accountKey, _ := master.DeriveFromPathString("m/44'/0'/0'")
	accountPub, _ := accountKey.Neuter()
	fmt.Printf("Account xpub: %s\n", accountPub.String())

	external, _ := accountPub.(*bip32.ExtendedKey).Child(0)
	addr0, _ := external.(*bip32.ExtendedKey).Child(0)
	addr1, _ := external.(*bip32.ExtendedKey).Child(1)

	fmt.Printf("Address 0: %x\n", addr0.PublicKeyBytes())
	fmt.Printf("Address 1: %x\n", addr1.PublicKeyBytes())
	fmt.Println()

	// 6. Parse extended key
	fmt.Println("--- Parse Extended Key ---")
	xprvStr := "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
	parsed, _ := bip32.ParseExtendedKey(xprvStr)
	fmt.Printf("Parsed:     %s\n", parsed.String())
	fmt.Printf("Is Private: %v\n", parsed.IsPrivate())
	fmt.Printf("Depth:      %d\n", parsed.Depth())
	fmt.Println()

	// 7. Key interface usage
	fmt.Println("--- Key Interface ---")
	var key bip32.Key = master
	fmt.Printf("IsPrivate:   %v\n", key.IsPrivate())
	fmt.Printf("Depth:       %d\n", key.Depth())
	fmt.Printf("Network:     %s\n", key.Network().Name)

	fmt.Println()
	fmt.Println("=== Complete ===")
}
