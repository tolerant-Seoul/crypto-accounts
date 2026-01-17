//! Solana Account Generation
//!
//! - 타원곡선: Ed25519
//! - 주소 형식: Base58 (공개키 = 주소)
//! - BIP-44 경로: m/44'/501'/0'/0'
//!
//! ## 주소 생성 과정
//! 1. 시드 → SLIP-10 Ed25519 도출
//! 2. Ed25519 개인키 (32바이트)
//! 3. 개인키 → Ed25519 공개키 (32바이트)
//! 4. 공개키 = 주소 (Base58 인코딩)
//!
//! ## SLIP-10 vs BIP-32
//! - BIP-32: secp256k1 전용
//! - SLIP-10: Ed25519용 수정 버전 (강화 도출만 지원)

use ed25519_dalek::{SigningKey, VerifyingKey};

use crate::bip39::mnemonic_to_seed;
use crate::utils::slip10::derive_ed25519_key;

/// Solana 계정
#[derive(Debug, Clone)]
pub struct SolanaAccount {
    /// 개인키 (32바이트)
    pub private_key: [u8; 32],
    /// 공개키 (32바이트) = 주소
    pub public_key: [u8; 32],
}

/// Solana 기본 도출 경로
pub const SOLANA_PATH: &str = "m/44'/501'/0'/0'";

impl SolanaAccount {
    /// 개인키에서 Solana 계정 생성
    pub fn from_private_key(private_key: [u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(&private_key);
        let verifying_key: VerifyingKey = (&signing_key).into();

        SolanaAccount {
            private_key,
            public_key: verifying_key.to_bytes(),
        }
    }

    /// 시드에서 Solana 계정 생성 (기본 경로)
    pub fn from_seed(seed: &[u8]) -> Result<Self, String> {
        Self::from_seed_with_path(seed, SOLANA_PATH)
    }

    /// 시드에서 특정 경로로 Solana 계정 생성 (SLIP-10)
    pub fn from_seed_with_path(seed: &[u8], path: &str) -> Result<Self, String> {
        let private_key = derive_ed25519_key(seed, path)?;
        Ok(Self::from_private_key(private_key))
    }

    /// 니모닉에서 Solana 계정 생성
    pub fn from_mnemonic(mnemonic: &str, passphrase: &str) -> Result<Self, String> {
        let seed = mnemonic_to_seed(mnemonic, passphrase);
        Self::from_seed(&seed)
    }

    /// 주소 반환 (Base58 인코딩된 공개키)
    pub fn address(&self) -> String {
        bs58::encode(&self.public_key).into_string()
    }

    /// 개인키를 hex로 반환
    pub fn private_key_hex(&self) -> String {
        hex::encode(self.private_key)
    }

    /// 공개키를 hex로 반환
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.public_key)
    }

    /// Keypair 바이트 반환 (개인키 + 공개키, 64바이트)
    /// Solana CLI 호환 형식
    pub fn keypair_bytes(&self) -> [u8; 64] {
        let mut keypair = [0u8; 64];
        keypair[..32].copy_from_slice(&self.private_key);
        keypair[32..].copy_from_slice(&self.public_key);
        keypair
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_solana_from_mnemonic() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        let account = SolanaAccount::from_mnemonic(mnemonic, "").unwrap();

        println!("=== Solana (m/44'/501'/0'/0') ===");
        println!("개인키: {}", account.private_key_hex());
        println!("공개키: {}", account.public_key_hex());
        println!("주소: {}", account.address());

        // Phantom 지갑 등에서 확인 가능한 주소
        // 참고: 지갑마다 경로가 다를 수 있음
    }

    #[test]
    fn test_multiple_accounts() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let seed = mnemonic_to_seed(mnemonic, "");

        println!("\n=== Solana 계정 목록 (첫 5개) ===\n");

        for i in 0..5 {
            let path = format!("m/44'/501'/{}'/0'", i);
            let account = SolanaAccount::from_seed_with_path(&seed, &path).unwrap();

            println!("경로: {}", path);
            println!("주소: {}", account.address());
            println!();
        }
    }

    #[test]
    fn test_keypair_format() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let account = SolanaAccount::from_mnemonic(mnemonic, "").unwrap();

        let keypair = account.keypair_bytes();
        assert_eq!(keypair.len(), 64);

        // 앞 32바이트 = 개인키
        assert_eq!(&keypair[..32], &account.private_key);
        // 뒤 32바이트 = 공개키
        assert_eq!(&keypair[32..], &account.public_key);

        println!("Keypair (JSON): {:?}", keypair.to_vec());
    }
}
