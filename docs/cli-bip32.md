# BIP-32 CLI Tool

BIP-32 HD Wallet CLI tool for testing key generation and derivation.

## Build

```bash
go build -o bin/bip32 ./cmd/bip32
```

## Commands

### generate - Generate Master Key

Generate a master key from a hex seed.

```bash
bip32 generate --seed <hex> [--network mainnet|testnet]
```

**Options:**
- `--seed`: Seed in hexadecimal (16-64 bytes)
- `--network`: Network type (default: mainnet)

**Example:**
```bash
# Generate master key with BIP-32 Test Vector 1
./bin/bip32 generate --seed 000102030405060708090a0b0c0d0e0f

# Output:
# === Master Key Generated ===
# Network:     mainnet
# Seed:        000102030405060708090a0b0c0d0e0f
#
# xprv:        xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi
# xpub:        xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8
#
# Private Key: e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35
# Public Key:  0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2
# Chain Code:  873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508
```

### derive - Derive Child Key

Derive a child key from an extended key using a derivation path.

```bash
bip32 derive --key <xprv/xpub> --path <path>
bip32 derive --key <xprv/xpub> --index <n> [--hardened]
```

**Options:**
- `--key`: Extended key (xprv or xpub)
- `--path`: Derivation path (e.g., m/44'/0'/0'/0/0)
- `--index`: Single child index (alternative to path)
- `--hardened`: Use hardened derivation for --index

**Example:**
```bash
# Derive using path
./bin/bip32 derive \
  --key "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi" \
  --path "m/0'"

# Derive using index
./bin/bip32 derive \
  --key "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi" \
  --index 0 --hardened
```

### parse - Parse Extended Key

Parse and display extended key information.

```bash
bip32 parse --key <xprv/xpub>
```

**Example:**
```bash
./bin/bip32 parse --key "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"

# Output:
# === Extended Key Info ===
#
# Type:        Public Extended Key
# Network:     mainnet
# Depth:       0
# Child Index: 0
# Fingerprint: 3442193e
# Parent FP:   00000000
#
# xpub:        xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8
#
# Public Key:  0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2
# Chain Code:  873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508
```

### info - Show Key Details

Show detailed key information including common derivation paths.

```bash
bip32 info --key <xprv/xpub>
```

**Example:**
```bash
./bin/bip32 info --key "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
```

For master keys (depth 0), this command also shows derived keys for common paths:
- Bitcoin (BIP-44): `m/44'/0'/0'/0/0`
- Ethereum (BIP-44): `m/44'/60'/0'/0/0`
- Bitcoin SegWit (BIP-84): `m/84'/0'/0'/0/0`

## Testing with BIP-32 Test Vectors

### Test Vector 1

**Seed:** `000102030405060708090a0b0c0d0e0f`

```bash
# Generate master key
./bin/bip32 generate --seed 000102030405060708090a0b0c0d0e0f
# Expected xprv: xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi
# Expected xpub: xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8

# Derive m/0'
./bin/bip32 derive --key "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi" --path "m/0'"
# Expected xprv: xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7
# Expected xpub: xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw

# Derive m/0'/1
./bin/bip32 derive --key "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7" --path "m/1"
# Expected xprv: xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs
# Expected xpub: xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ

# Derive m/0'/1/2'
./bin/bip32 derive --key "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs" --path "m/2'"
# Expected xprv: xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM
# Expected xpub: xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5
```

### Test Vector 2

**Seed:** `fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542`

```bash
# Generate master key
./bin/bip32 generate --seed fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542
# Expected xprv: xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U
# Expected xpub: xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB
```

### Test Vector 3 (Testnet)

```bash
# Generate testnet master key
./bin/bip32 generate --seed 000102030405060708090a0b0c0d0e0f --network testnet
# Expected tprv: tprv8ZgxMBicQKsPeDgjzdC36fs6bMjGApWDNLR9erAXMs5skhMv36j9MV5ecvfavji5khqjWaWSFhN3YcCUUdiKH6isR4Pwy3U5y5egddBr16m
# Expected tpub: tpubD6NzVbkrYhZ4XgiXtGrdW5XDAPFCL9h7we1vwNCpn8tGbBcgfVYjXyhWo4E1xkh56hjod1RhGjxbaTLV3X4FyWuejifB9jusQ46QzG87VKp
```

## Network Prefixes

| Network | Private Key Prefix | Public Key Prefix |
|---------|-------------------|-------------------|
| Mainnet | xprv | xpub |
| Testnet | tprv | tpub |

## Derivation Path Notation

- `m` - Master key
- `/` - Path separator
- `'` or `h` - Hardened derivation
- Number - Child index

**Examples:**
- `m/44'/0'/0'/0/0` - Bitcoin first address (BIP-44)
- `m/44'/60'/0'/0/0` - Ethereum first address (BIP-44)
- `m/84'/0'/0'/0/0` - Bitcoin SegWit first address (BIP-84)

## Related Documentation

- [BIP-32 Specification](./bip-0032.md)
- [BIP-39 Mnemonic](./bip-0039.md)
- [BIP-44 Multi-Account](./bip-0044.md)
