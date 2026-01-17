//! Sui Account Generation
//!
//! - 타원곡선: Ed25519 (기본) 또는 secp256k1
//! - 해시: Blake2b-256
//! - 주소 형식: 32바이트 (0x...)
//! - BIP-44 경로: m/44'/784'/0'/0'/0'
//!
//! ## 주소 생성 과정
//! 1. 시드 → SLIP-10 Ed25519 도출
//! 2. Ed25519 개인키 → 공개키
//! 3. flag(0x00) + 공개키 → Blake2b-256 해시 = 주소
//!
//! ## 서명 스킴 플래그
//! - 0x00: Ed25519
//! - 0x01: Secp256k1
//! - 0x02: Secp256r1
//! - 0x03: MultiSig

use blake2::{Blake2b, Digest};
use blake2::digest::consts::U32;
use ed25519_dalek::{SigningKey, VerifyingKey};

use crate::bip39::mnemonic_to_seed;
use crate::utils::slip10::derive_ed25519_key;
use crate::utils::bech32::encode_bech32;

type Blake2b256 = Blake2b<U32>;

/// Sui 계정
#[derive(Debug, Clone)]
pub struct SuiAccount {
    /// 개인키 (32바이트)
    pub private_key: [u8; 32],
    /// 공개키 (32바이트)
    pub public_key: [u8; 32],
    /// 주소 (32바이트) - Blake2b-256(flag + pubkey)
    pub address: [u8; 32],
}

/// Sui 기본 도출 경로
pub const SUI_PATH: &str = "m/44'/784'/0'/0'/0'";

/// 서명 스킴 플래그
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SignatureScheme {
    Ed25519 = 0x00,
    Secp256k1 = 0x01,
    Secp256r1 = 0x02,
}

impl SuiAccount {
    /// 개인키에서 Sui 계정 생성
    pub fn from_private_key(private_key: [u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(&private_key);
        let verifying_key: VerifyingKey = (&signing_key).into();
        let public_key = verifying_key.to_bytes();

        // 주소 = Blake2b-256(flag + pubkey)
        let address = derive_sui_address(&public_key, SignatureScheme::Ed25519);

        SuiAccount {
            private_key,
            public_key,
            address,
        }
    }

    /// 시드에서 Sui 계정 생성 (기본 경로)
    pub fn from_seed(seed: &[u8]) -> Result<Self, String> {
        Self::from_seed_with_path(seed, SUI_PATH)
    }

    /// 시드에서 특정 경로로 Sui 계정 생성 (SLIP-10)
    pub fn from_seed_with_path(seed: &[u8], path: &str) -> Result<Self, String> {
        let private_key = derive_ed25519_key(seed, path)?;
        Ok(Self::from_private_key(private_key))
    }

    /// 니모닉에서 Sui 계정 생성
    pub fn from_mnemonic(mnemonic: &str, passphrase: &str) -> Result<Self, String> {
        let seed = mnemonic_to_seed(mnemonic, passphrase);
        Self::from_seed(&seed)
    }

    /// 주소 반환 (0x 접두사)
    pub fn address(&self) -> String {
        format!("0x{}", hex::encode(self.address))
    }

    /// 주소 반환 (접두사 없이)
    pub fn address_hex(&self) -> String {
        hex::encode(self.address)
    }

    /// 개인키를 hex로 반환
    pub fn private_key_hex(&self) -> String {
        hex::encode(self.private_key)
    }

    /// 공개키를 hex로 반환
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.public_key)
    }

    /// Sui 형식의 개인키 (suiprivkey...) - Bech32 인코딩
    pub fn private_key_bech32(&self) -> String {
        // flag + private_key
        let mut data = vec![SignatureScheme::Ed25519 as u8];
        data.extend_from_slice(&self.private_key);

        // Bech32 인코딩 (hrp = "suiprivkey")
        encode_bech32("suiprivkey", None, &data)
    }
}

// ═══════════════════════════════════════════════════════════════
// 주소 도출
// ═══════════════════════════════════════════════════════════════

/// Sui 주소 도출
///
/// address = Blake2b-256(flag || public_key)
fn derive_sui_address(public_key: &[u8; 32], scheme: SignatureScheme) -> [u8; 32] {
    let mut hasher = Blake2b256::new();

    // flag + public_key
    hasher.update([scheme as u8]);
    hasher.update(public_key);

    let result = hasher.finalize();
    let mut address = [0u8; 32];
    address.copy_from_slice(&result);

    address
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sui_from_mnemonic() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        let account = SuiAccount::from_mnemonic(mnemonic, "").unwrap();

        println!("=== Sui (m/44'/784'/0'/0'/0') ===");
        println!("개인키: {}", account.private_key_hex());
        println!("공개키: {}", account.public_key_hex());
        println!("주소: {}", account.address());
        println!("Bech32 개인키: {}", account.private_key_bech32());
    }

    #[test]
    fn test_sui_address_derivation() {
        // 알려진 공개키로 주소 도출 테스트
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let account = SuiAccount::from_mnemonic(mnemonic, "").unwrap();

        // 주소가 32바이트인지 확인
        assert_eq!(account.address.len(), 32);

        // 0x로 시작하는지 확인
        assert!(account.address().starts_with("0x"));

        println!("주소 길이: {} 문자", account.address().len());
    }

    #[test]
    fn test_multiple_accounts() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let seed = mnemonic_to_seed(mnemonic, "");

        println!("\n=== Sui 계정 목록 (첫 5개) ===\n");

        for i in 0..5 {
            let path = format!("m/44'/784'/0'/0'/{}'", i);
            let account = SuiAccount::from_seed_with_path(&seed, &path).unwrap();

            println!("경로: {}", path);
            println!("주소: {}", account.address());
            println!();
        }
    }

    #[test]
    fn test_blake2b_hash() {
        // Blake2b-256 기본 테스트
        let mut hasher = Blake2b256::new();
        hasher.update(b"test");
        let result = hasher.finalize();

        assert_eq!(result.len(), 32);
        println!("Blake2b-256(\"test\"): {}", hex::encode(result));
    }
}
