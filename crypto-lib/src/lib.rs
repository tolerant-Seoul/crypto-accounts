//! # Crypto Lib
//!
//! 블록체인 계정 생성 라이브러리 - 암호학 학습용
//!
//! ## 지원 체인
//! - Bitcoin (secp256k1 + RIPEMD-160)
//! - EVM (secp256k1 + Keccak-256)
//! - Solana (Ed25519)
//! - Sui (Ed25519 + Blake2b)
//! - Cosmos (secp256k1 + Bech32)

pub mod bip39;
pub mod bip32;

pub mod utils;

pub mod bitcoin;
pub mod evm;
pub mod solana;
pub mod sui;
pub mod cosmos;
