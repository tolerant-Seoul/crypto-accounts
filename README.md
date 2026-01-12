# Crypto Accounts

Multi-chain cryptocurrency address generator implementing BIP-32, BIP-39, and BIP-44 standards in Go.

## Features

- BIP-32 HD (Hierarchical Deterministic) wallet key derivation
- BIP-39 mnemonic seed phrase generation and recovery
- BIP-44 multi-account hierarchy for deterministic wallets
- Support for 38+ blockchain networks
- Address generation and validation for each supported chain

## Supported Chains

### Bitcoin Family (Base58Check/Bech32)

| Chain | Symbol | Address Format | Prefix |
|-------|--------|----------------|--------|
| Bitcoin | BTC | P2PKH, P2SH, Bech32 | `1`, `3`, `bc1` |
| Litecoin | LTC | P2PKH, P2SH, Bech32 | `L`, `M`, `ltc1` |
| Dogecoin | DOGE | P2PKH | `D` |
| Bitcoin Cash | BCH | CashAddr | `bitcoincash:` |
| Zcash | ZEC | Transparent | `t1`, `t3` |

### EVM Compatible (Keccak256)

| Chain | Symbol | Address Format |
|-------|--------|----------------|
| Ethereum | ETH | 0x-prefixed, EIP-55 checksum |
| BNB Smart Chain | BNB | Same as Ethereum |
| Polygon | MATIC | Same as Ethereum |
| Fantom | FTM | Same as Ethereum |
| Optimism | OP | Same as Ethereum |
| Arbitrum | ARB | Same as Ethereum |
| VeChain | VET | Same as Ethereum |
| Theta | THETA | Same as Ethereum |
| Ethereum Classic | ETC | Same as Ethereum |
| Avalanche C-Chain | AVAX | Same as Ethereum |

### Cosmos Family (Bech32)

| Chain | Symbol | HRP |
|-------|--------|-----|
| Cosmos | ATOM | `cosmos` |
| Binance BEP2 | BNB | `bnb` |
| Sei | SEI | `sei` |

### Ed25519 Based

| Chain | Symbol | Address Format |
|-------|--------|----------------|
| Solana | SOL | Base58, 32-44 chars |
| Stellar | XLM | Base32, starts with `G` |
| Algorand | ALGO | Base32, 58 chars |
| NEAR | NEAR | Hex (64 chars) or named |
| Cardano | ADA | Bech32, starts with `addr1` |

### Polkadot Family (SS58)

| Chain | Symbol | Address Format |
|-------|--------|----------------|
| Polkadot | DOT | SS58 encoded |

### Move-based Chains

| Chain | Symbol | Address Format |
|-------|--------|----------------|
| Aptos | APT | 0x-prefixed, 64 hex chars |
| Sui | SUI | 0x-prefixed, 64 hex chars |

### Other Chains

| Chain | Symbol | Address Format | Prefix/Note |
|-------|--------|----------------|-------------|
| TRON | TRX | Base58Check | `T` |
| Ripple | XRP | Base58 (Ripple variant) | `r` |
| Tezos | XTZ | Base58Check + Blake2b | `tz1`, `tz2`, `tz3` |
| Kaspa | KAS | Bech32 | `kaspa1` |
| Stacks | STX | c32check | `S` |
| Filecoin | FIL | Base32 | `f1`, `f3` |
| Hedera | HBAR | Account ID | `0.0.xxxxx` |
| ICP | ICP | Principal ID (Base32) | - |
| EOS | EOS | Account Names / PUB_K1 | 12-char names |
| Flow | FLOW | Hex | `0x` (16 chars) |
| Arweave | AR | Base64URL (SHA-256) | 43 chars |
| Monero | XMR | Base58 (Monero variant) | `4` (95 chars) |

## Installation

```bash
go get github.com/study/crypto-accounts
```

## Usage

### Generate Address

```go
package main

import (
    "fmt"
    "github.com/study/crypto-accounts/pkgs/address"
)

func main() {
    factory := address.NewFactory()

    // Generate Ethereum address from public key
    publicKey := []byte{...} // 64-byte uncompressed public key
    addr, err := factory.Generate(address.ChainEthereum, publicKey)
    if err != nil {
        panic(err)
    }
    fmt.Println("Ethereum address:", addr)
}
```

### Validate Address

```go
package main

import (
    "fmt"
    "github.com/study/crypto-accounts/pkgs/address"
)

func main() {
    factory := address.NewFactory()

    // Validate Bitcoin address
    isValid := factory.Validate(address.ChainBitcoin, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
    fmt.Println("Valid:", isValid)
}
```

### HD Wallet Key Derivation

```go
package main

import (
    "fmt"
    "github.com/study/crypto-accounts/pkgs/bip32"
    "github.com/study/crypto-accounts/pkgs/bip39"
)

func main() {
    // Generate mnemonic
    mnemonic, _ := bip39.NewMnemonic(128) // 12 words

    // Derive seed
    seed := bip39.NewSeed(mnemonic, "")

    // Create master key
    masterKey, _ := bip32.NewMasterKey(seed)

    // Derive BIP-44 path: m/44'/60'/0'/0/0 (Ethereum)
    key, _ := masterKey.Derive(bip32.HardenedKeyStart + 44)
    key, _ = key.Derive(bip32.HardenedKeyStart + 60)
    key, _ = key.Derive(bip32.HardenedKeyStart + 0)
    key, _ = key.Derive(0)
    key, _ = key.Derive(0)

    fmt.Println("Public Key:", key.PublicKey())
}
```

## Building

```bash
make build
```

## Testing

```bash
make test
```

## Documentation

- [BIP-32 Specification](docs/spec/bip-0032.md)
- [BIP-39 Specification](docs/spec/bip-0039.md)
- [BIP-43 Specification](docs/spec/bip-0043.md)
- [BIP-44 Specification](docs/spec/bip-0044.md)
- [Chain-Specific Address Generation](docs/chain-specific-addresses.md)

## License

MIT License - see [LICENSE](LICENSE) for details.
