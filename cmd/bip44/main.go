// BIP-44 CLI tool for testing multi-account hierarchy derivation
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/study/crypto-accounts/pkgs/bip44"
)

const usage = `BIP-44 Multi-Account CLI Tool

Usage:
  bip44 <command> [options]

Commands:
  derive      Derive addresses from mnemonic
  account     Show account information
  coins       List supported coin types
  parse       Parse and display path info

Examples:
  # Derive Bitcoin addresses from mnemonic
  bip44 derive --mnemonic "abandon abandon ... about" --coin btc

  # Derive Ethereum addresses
  bip44 derive --mnemonic "abandon abandon ... about" --coin eth --count 5

  # Show account information
  bip44 account --mnemonic "abandon abandon ... about" --coin eth --account 0

  # List supported coins
  bip44 coins

  # Parse BIP-44 path
  bip44 parse --path "m/44'/60'/0'/0/0"
`

func main() {
	if len(os.Args) < 2 {
		fmt.Print(usage)
		os.Exit(1)
	}

	switch os.Args[1] {
	case "derive":
		cmdDerive(os.Args[2:])
	case "account":
		cmdAccount(os.Args[2:])
	case "coins":
		cmdCoins(os.Args[2:])
	case "parse":
		cmdParse(os.Args[2:])
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Printf("Unknown command: %s\n\n", os.Args[1])
		fmt.Print(usage)
		os.Exit(1)
	}
}

func cmdDerive(args []string) {
	fs := flag.NewFlagSet("derive", flag.ExitOnError)
	mnemonic := fs.String("mnemonic", "", "Mnemonic phrase")
	passphrase := fs.String("passphrase", "", "Optional passphrase")
	coin := fs.String("coin", "btc", "Coin type (btc, eth, ltc, etc.)")
	account := fs.Uint("account", 0, "Account index")
	change := fs.Uint("change", 0, "Change type (0=external, 1=internal)")
	startIndex := fs.Uint("start", 0, "Start address index")
	count := fs.Uint("count", 5, "Number of addresses to derive")
	fs.Parse(args)

	if *mnemonic == "" {
		fmt.Println("Error: --mnemonic is required")
		os.Exit(1)
	}

	coinType, err := parseCoinType(*coin)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	wallet, err := bip44.NewWalletFromMnemonic(*mnemonic, *passphrase)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	coinInfo := bip44.GetCoinInfo(coinType)
	coinName := "Unknown"
	if coinInfo != nil {
		coinName = coinInfo.Name
	}

	fmt.Printf("=== %s Addresses ===\n", coinName)
	fmt.Printf("Account: %d, Change: %d\n", *account, *change)
	fmt.Println()

	addresses, err := wallet.DeriveAddresses(coinType, uint32(*account), uint32(*change), uint32(*startIndex), uint32(*count))
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	for _, addr := range addresses {
		fmt.Printf("Path: %s\n", addr.Path.String())
		fmt.Printf("  Private: %s\n", hex.EncodeToString(addr.PrivateKey))
		fmt.Printf("  Public:  %s\n", hex.EncodeToString(addr.PublicKey))
		fmt.Println()
	}
}

func cmdAccount(args []string) {
	fs := flag.NewFlagSet("account", flag.ExitOnError)
	mnemonic := fs.String("mnemonic", "", "Mnemonic phrase")
	passphrase := fs.String("passphrase", "", "Optional passphrase")
	coin := fs.String("coin", "btc", "Coin type (btc, eth, ltc, etc.)")
	accountIdx := fs.Uint("account", 0, "Account index")
	fs.Parse(args)

	if *mnemonic == "" {
		fmt.Println("Error: --mnemonic is required")
		os.Exit(1)
	}

	coinType, err := parseCoinType(*coin)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	wallet, err := bip44.NewWalletFromMnemonic(*mnemonic, *passphrase)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	account, err := wallet.DeriveAccount(coinType, uint32(*accountIdx))
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	coinInfo := bip44.GetCoinInfo(coinType)
	coinName := "Unknown"
	symbol := ""
	if coinInfo != nil {
		coinName = coinInfo.Name
		symbol = coinInfo.Symbol
	}

	fmt.Printf("=== %s Account %d ===\n", coinName, *accountIdx)
	fmt.Println()

	path := bip44.NewPath(coinType, uint32(*accountIdx), 0, 0)
	fmt.Printf("Coin:        %s (%s)\n", coinName, symbol)
	fmt.Printf("Coin Type:   %d\n", coinType)
	fmt.Printf("Account:     %d\n", *accountIdx)
	fmt.Printf("Account Path: %s\n", path.AccountPath())
	fmt.Println()

	fmt.Printf("Account xprv: %s\n", account.Key().String())
	pub, _ := account.PublicKey()
	fmt.Printf("Account xpub: %s\n", pub.String())
	fmt.Println()

	// Show first few addresses
	fmt.Println("=== First 3 External Addresses ===")
	for i := uint32(0); i < 3; i++ {
		info, _ := account.GetAddressInfo(bip44.ExternalChain, i)
		fmt.Printf("\n%s\n", info.Path.String())
		fmt.Printf("  Private: %s\n", hex.EncodeToString(info.PrivateKey))
		fmt.Printf("  Public:  %s\n", hex.EncodeToString(info.PublicKey))
	}
}

func cmdCoins(args []string) {
	coins := bip44.ListCoins()

	// Sort by coin type
	sort.Slice(coins, func(i, j int) bool {
		return coins[i].Type < coins[j].Type
	})

	fmt.Println("=== Supported Coin Types ===")
	fmt.Println()
	fmt.Printf("%-6s %-8s %-20s %s\n", "Type", "Symbol", "Name", "Decimals")
	fmt.Println(strings.Repeat("-", 50))

	for _, coin := range coins {
		fmt.Printf("%-6d %-8s %-20s %d\n", coin.Type, coin.Symbol, coin.Name, coin.Decimals)
	}
	fmt.Println()

	fmt.Println("Common aliases:")
	fmt.Println("  btc, bitcoin   -> Bitcoin (0)")
	fmt.Println("  eth, ethereum  -> Ethereum (60)")
	fmt.Println("  ltc, litecoin  -> Litecoin (2)")
	fmt.Println("  doge, dogecoin -> Dogecoin (3)")
}

func cmdParse(args []string) {
	fs := flag.NewFlagSet("parse", flag.ExitOnError)
	pathStr := fs.String("path", "", "BIP-44 path to parse")
	fs.Parse(args)

	if *pathStr == "" {
		fmt.Println("Error: --path is required")
		os.Exit(1)
	}

	path, err := bip44.ParsePath(*pathStr)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	coinInfo := bip44.GetCoinInfo(path.CoinType)
	coinName := "Unknown"
	symbol := ""
	if coinInfo != nil {
		coinName = coinInfo.Name
		symbol = coinInfo.Symbol
	}

	changeType := "External (receiving)"
	if path.Change == bip44.InternalChain {
		changeType = "Internal (change)"
	}

	fmt.Println("=== BIP-44 Path Info ===")
	fmt.Println()
	fmt.Printf("Path:          %s\n", path.String())
	fmt.Println()
	fmt.Printf("Purpose:       %d' (BIP-44)\n", path.Purpose)
	fmt.Printf("Coin Type:     %d' (%s - %s)\n", path.CoinType, coinName, symbol)
	fmt.Printf("Account:       %d'\n", path.Account)
	fmt.Printf("Change:        %d (%s)\n", path.Change, changeType)
	fmt.Printf("Address Index: %d\n", path.AddressIndex)
	fmt.Println()
	fmt.Printf("Account Path:  %s\n", path.AccountPath())
}

func parseCoinType(coin string) (bip44.CoinType, error) {
	coin = strings.ToLower(strings.TrimSpace(coin))

	switch coin {
	case "btc", "bitcoin":
		return bip44.CoinTypeBitcoin, nil
	case "eth", "ethereum":
		return bip44.CoinTypeEthereum, nil
	case "ltc", "litecoin":
		return bip44.CoinTypeLitecoin, nil
	case "doge", "dogecoin":
		return bip44.CoinTypeDogecoin, nil
	case "dash":
		return bip44.CoinTypeDash, nil
	case "etc":
		return bip44.CoinTypeEthereumClassic, nil
	case "xrp", "ripple":
		return bip44.CoinTypeRipple, nil
	case "bch", "bitcoincash":
		return bip44.CoinTypeBitcoinCash, nil
	case "xlm", "stellar":
		return bip44.CoinTypeStellar, nil
	case "trx", "tron":
		return bip44.CoinTypeTron, nil
	case "bnb", "binance":
		return bip44.CoinTypeBinance, nil
	case "sol", "solana":
		return bip44.CoinTypeSolana, nil
	case "matic", "polygon":
		return bip44.CoinTypePolygon, nil
	case "avax", "avalanche":
		return bip44.CoinTypeAvalanche, nil
	case "test", "testnet":
		return bip44.CoinTypeTestnet, nil
	default:
		return 0, fmt.Errorf("unknown coin type: %s", coin)
	}
}
