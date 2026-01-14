# Crypto Accounts

## 프로젝트 목표

블록체인 계정 생성 과정을 직접 구현하며 암호학 기초를 학습한다.
[Ian Coleman BIP39](https://iancoleman.io/bip39/)처럼 동작하는 도구를 만든다.

### 학습 로드맵

1. **Account** - 니모닉 → 키 도출 → 주소 생성 (현재)
2. **Transaction** - 가스, 서명
3. **추후 확장** - ZK, 기타 암호학 응용

## 지원 체인

| 체인 | 타원곡선 | 해시 | 주소 형식 | BIP-44 경로 |
|------|---------|------|----------|-------------|
| **Bitcoin** | secp256k1 | SHA-256 + RIPEMD-160 | Base58/Bech32 | m/84'/0'/0' (SegWit) |
| **EVM** | secp256k1 | Keccak-256 | 20바이트 (0x...) | m/44'/60'/0' |
| **Solana** | Ed25519 | SHA-256 | Base58 | m/44'/501'/0' |
| **Sui** | Ed25519 | Blake2b | 32바이트 (0x...) | m/44'/784'/0' |
| **Cosmos** | secp256k1 | SHA-256 + RIPEMD-160 | Bech32 | m/44'/118'/0' |

## 프로젝트 구조

```text
crypto-accounts/
├── CLAUDE.md
├── LICENSE
├── crypto-lib/                 # Rust 라이브러리 (암호학 학습용)
│   ├── src/
│   │   ├── lib.rs
│   │   ├── bip39.rs           # 니모닉 생성
│   │   ├── bip32.rs           # HD 키 도출
│   │   ├── bitcoin/           # secp256k1 + RIPEMD-160
│   │   ├── evm/               # secp256k1 + Keccak-256
│   │   ├── solana/            # Ed25519
│   │   ├── sui/               # Ed25519 + Blake2b
│   │   └── cosmos/            # secp256k1 + Bech32
│   └── Cargo.toml
│
├── web/                        # JavaScript 웹 UI
├── docs/                       # BIP 문서
└── notes/                      # 학습 노트
```

## 기술 스택

- **암호학 라이브러리:** Rust (직접 구현하며 학습)
- **웹 UI:** JavaScript (빠른 개발, 결과 확인용)
- **추후:** Rust → WASM 바인딩 (옵션)

## 참고 자료

- [BIP-32: HD Wallets](./docs/bip-0032.md)
- [BIP-39: Mnemonic](./docs/bip-0039.md)
- [BIP-43: Purpose Field](./docs/bip-0043.md)
- [BIP-44: Multi-Account](./docs/bip-0044.md)
